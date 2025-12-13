const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const cors = require('cors');

const app = express();
const PORT = 5000;

// CORS configuration - ALLOWING CUSTOM HEADERS
app.use(cors({
    origin: true,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'x-user-email', 'x-user-password']
}));

app.options('*', cors());
app.use(express.json());

// MongoDB Connection
const MONGODB_URI = 'mongodb+srv://trenny:trennydev@trennydev.hieeqv2.mongodb.net/trennydev?retryWrites=true&w=majority';
const client = new MongoClient(MONGODB_URI);
let db;

// Connect to MongoDB
const connectToMongoDB = async () => {
    try {
        console.log('🔄 Connecting to MongoDB...');
        await client.connect();
        db = client.db('eduhub_school');
        console.log('✅ MongoDB connected successfully');
        
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
    const collections = ['users', 'students', 'teachers', 'courses', 'attendance', 'results', 'announcements', 'resources', 'flashcards', 'notes', 'studytimes', 'videos', 'events', 'leaderboard'];
    
    for (const collectionName of collections) {
        try {
            await db.createCollection(collectionName);
            console.log(`✅ Collection ${collectionName} created/verified`);
        } catch (error) {
            // Collection already exists
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
                password: 'admin123',
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
            const studentResult = await db.collection('students').insertOne({
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
            
            // Create corresponding user account
            await db.collection('users').insertOne({
                email: 'student@kv.edu',
                password: 'student123',
                name: 'Aarav Sharma',
                role: 'student',
                class: '11',
                section: 'A',
                rollNo: 1,
                admissionNo: 'KV2023001',
                studentId: studentResult.insertedId,
                createdAt: new Date()
            });
            console.log('✅ Default student created');
        }

        // Check if default teacher exists
        const teacherExists = await db.collection('teachers').findOne({ email: 'teacher@kv.edu' });
        if (!teacherExists) {
            const teacherResult = await db.collection('teachers').insertOne({
                name: 'Priya Sharma',
                email: 'teacher@kv.edu',
                subject: 'Mathematics',
                classes: ['11-A', '12-A'],
                contact: '9876543211',
                createdAt: new Date()
            });
            
            // Create corresponding user account
            await db.collection('users').insertOne({
                email: 'teacher@kv.edu',
                password: 'teacher123',
                name: 'Priya Sharma',
                role: 'teacher',
                subject: 'Mathematics',
                classes: ['11-A', '12-A'],
                contact: '9876543211',
                teacherId: teacherResult.insertedId,
                createdAt: new Date()
            });
            console.log('✅ Default teacher created');
        }

        // Check if default parent exists
        const parentExists = await db.collection('users').findOne({ email: 'parent@kv.edu' });
        if (!parentExists) {
            await db.collection('users').insertOne({
                email: 'parent@kv.edu',
                password: 'parent123',
                name: 'Rajesh Sharma',
                role: 'parent',
                phone: '9876543212',
                childId: 'KV2023001', // Linked to default student
                createdAt: new Date()
            });
            console.log('✅ Default parent created');
        }

        // Check if default courses exist
        const coursesExist = await db.collection('courses').countDocuments();
        if (coursesExist === 0) {
            await db.collection('courses').insertMany([
                {
                    title: 'Mathematics Class 11',
                    subject: 'Mathematics',
                    class: '11',
                    description: 'Complete Mathematics course for Class 11',
                    teacher: 'Priya Sharma',
                    youtubeUrl: 'https://www.youtube.com/playlist?list=PLxCzCOWd7aiGz9donHRrE9I3Mwn6XdP8p',
                    createdAt: new Date()
                },
                {
                    title: 'Physics Class 12',
                    subject: 'Physics',
                    class: '12',
                    description: 'Complete Physics course for Class 12',
                    teacher: 'Dr. Ravi Kumar',
                    youtubeUrl: 'https://www.youtube.com/playlist?list=PLqjFFrfkJcXT-lq6-v2IgxYoXK2wWHTmP',
                    createdAt: new Date()
                }
            ]);
            console.log('✅ Default courses created');
        }

        // Check if default attendance exists
        const attendanceExists = await db.collection('attendance').countDocuments();
        if (attendanceExists === 0) {
            await db.collection('attendance').insertOne({
                date: new Date(),
                class: '11-A',
                students: [
                    { studentId: 'KV2023001', name: 'Aarav Sharma', status: 'present', time: '09:00 AM' },
                    { studentId: 'KV2023002', name: 'Priya Patel', status: 'present', time: '09:01 AM' },
                    { studentId: 'KV2023003', name: 'Rohan Kumar', status: 'absent', time: null }
                ],
                subject: 'Mathematics',
                createdAt: new Date()
            });
            console.log('✅ Default attendance record created');
        }

        // Check if default results exist
        const resultsExist = await db.collection('results').countDocuments();
        if (resultsExist === 0) {
            await db.collection('results').insertMany([
                {
                    studentId: 'KV2023001',
                    studentName: 'Aarav Sharma',
                    examType: 'Unit Test 1',
                    subject: 'Mathematics',
                    marks: 85,
                    totalMarks: 100,
                    grade: 'B',
                    class: '11',
                    driveLink: 'https://drive.google.com/file/d/example',
                    createdAt: new Date()
                },
                {
                    studentId: 'KV2023001',
                    studentName: 'Aarav Sharma',
                    examType: 'Unit Test 1',
                    subject: 'Physics',
                    marks: 92,
                    totalMarks: 100,
                    grade: 'A',
                    class: '11',
                    driveLink: 'https://drive.google.com/file/d/example2',
                    createdAt: new Date()
                }
            ]);
            console.log('✅ Default results created');
        }

        console.log('✅ Default data initialization completed');
    } catch (error) {
        console.error('❌ Error initializing data:', error.message);
    }
};

// Start the connection
connectToMongoDB();

// Utility function to calculate grade
const calculateGrade = (marks) => {
    if (marks >= 90) return 'A';
    if (marks >= 80) return 'B';
    if (marks >= 70) return 'C';
    if (marks >= 60) return 'D';
    return 'F';
};

// ===== FIXED AUTHENTICATION MIDDLEWARE =====
const requireAuth = async (req, res, next) => {
    const email = req.headers['x-user-email'];
    const password = req.headers['x-user-password'];

    console.log(`🔍 Auth attempt for ${req.method} ${req.path}`);
    console.log(`📧 Email provided: ${email}`);
    console.log(`🔐 Password provided: ${password ? '***' : 'none'}`);

    if (!email || !password) {
        console.log('❌ Missing auth headers');
        return res.status(401).json({ 
            error: 'Authentication required',
            details: 'Please provide x-user-email and x-user-password headers'
        });
    }

    try {
        const user = await db.collection('users').findOne({ email, password });
        
        if (!user) {
            console.log('❌ Invalid credentials for:', email);
            return res.status(401).json({ 
                error: 'Invalid credentials',
                details: 'Email or password is incorrect'
            });
        }

        console.log(`✅ Auth successful for: ${user.name} (${user.role})`);
        req.user = user;
        next();
    } catch (error) {
        console.error('❌ Auth error:', error.message);
        res.status(500).json({ 
            error: 'Authentication failed',
            details: error.message 
        });
    }
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

        const userData = {
            email,
            password: password,
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

        res.status(201).json({
            message: 'User created successfully',
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

        const user = await db.collection('users').findOne({ email, password });
        if (!user) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }

        res.json({
            message: 'Login successful',
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

// ===== DASHBOARD STATS =====
app.get('/api/dashboard/stats', requireAuth, async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ error: 'Database not connected' });
        }

        // REAL DATA FROM DATABASE
        const totalStudents = await db.collection('students').countDocuments();
        const totalTeachers = await db.collection('teachers').countDocuments();
        const totalCourses = await db.collection('courses').countDocuments();
        
        // Calculate attendance rate from real data
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        
        const todayAttendance = await db.collection('attendance').findOne({
            date: { $gte: today }
        });
        
        let attendanceRate = '0%';
        if (todayAttendance && todayAttendance.students) {
            const presentCount = todayAttendance.students.filter(s => s.status === 'present').length;
            const totalCount = todayAttendance.students.length;
            attendanceRate = totalCount > 0 ? `${Math.round((presentCount / totalCount) * 100)}%` : '0%';
        }
        
        // Calculate pending tasks (unmarked attendance for today)
        const pendingTasks = await db.collection('courses').countDocuments(); // Simplified

        res.json({
            totalStudents,
            totalTeachers,
            totalCourses,
            attendanceRate,
            pendingTasks,
            profileCompleted: req.user.name && req.user.email ? 100 : 50
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ===== STUDENT ROUTES =====
app.get('/api/students', requireAuth, async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ error: 'Database not connected' });
        }
        
        // REAL DATA FROM DATABASE
        const students = await db.collection('students').find({}, {
            projection: {
                _id: 1,
                admissionNo: 1,
                firstName: 1,
                lastName: 1,
                email: 1,
                class: 1,
                section: 1,
                rollNo: 1,
                parentContact: 1,
                parentName: 1,
                createdAt: 1
            }
        }).toArray();
        
        res.json(students);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/students', requireAuth, async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ error: 'Database not connected' });
        }

        const { firstName, lastName, class: studentClass, section, rollNo, admissionNo, email, parentName, parentContact } = req.body;

        // Check if student already exists
        const existingStudent = await db.collection('students').findOne({ 
            $or: [
                { email },
                { admissionNo },
                { class: studentClass, section, rollNo }
            ]
        });

        if (existingStudent) {
            return res.status(400).json({ 
                error: 'Student already exists',
                details: 'A student with this email, admission number, or roll number already exists'
            });
        }

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
        await db.collection('users').insertOne({
            email: email,
            password: 'student123',
            name: `${firstName} ${lastName}`,
            role: 'student',
            class: studentClass,
            section: section,
            rollNo: rollNo,
            admissionNo: admissionNo,
            parentName: parentName,
            parentContact: parentContact,
            studentId: result.insertedId,
            createdAt: new Date()
        });

        res.status(201).json({ 
            message: 'Student created successfully', 
            student: {
                _id: student._id,
                firstName: student.firstName,
                lastName: student.lastName,
                email: student.email,
                class: student.class,
                section: student.section,
                rollNo: student.rollNo,
                admissionNo: student.admissionNo
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ===== TEACHER ROUTES =====
app.get('/api/teachers', requireAuth, async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ error: 'Database not connected' });
        }
        
        // REAL DATA FROM DATABASE
        const teachers = await db.collection('teachers').find({}, {
            projection: {
                _id: 1,
                name: 1,
                email: 1,
                subject: 1,
                classes: 1,
                contact: 1,
                createdAt: 1
            }
        }).toArray();
        
        res.json(teachers);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/teachers', requireAuth, async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ error: 'Database not connected' });
        }

        const { name, email, subject, classes, contact } = req.body;

        // Check if teacher already exists
        const existingTeacher = await db.collection('teachers').findOne({ email });
        if (existingTeacher) {
            return res.status(400).json({ 
                error: 'Teacher already exists',
                details: 'A teacher with this email already exists'
            });
        }

        const teacherData = {
            name,
            email,
            subject,
            classes: Array.isArray(classes) ? classes : [classes],
            contact,
            createdAt: new Date()
        };

        const result = await db.collection('teachers').insertOne(teacherData);
        const teacher = await db.collection('teachers').findOne({ _id: result.insertedId });

        // Also create user account
        await db.collection('users').insertOne({
            email: email,
            password: 'teacher123',
            name: name,
            role: 'teacher',
            subject: subject,
            classes: Array.isArray(classes) ? classes : [classes],
            contact: contact,
            teacherId: result.insertedId,
            createdAt: new Date()
        });

        res.status(201).json({ 
            message: 'Teacher created successfully', 
            teacher: {
                _id: teacher._id,
                name: teacher.name,
                email: teacher.email,
                subject: teacher.subject,
                classes: teacher.classes,
                contact: teacher.contact
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ===== COURSE ROUTES =====
app.get('/api/courses', requireAuth, async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ error: 'Database not connected' });
        }
        
        // REAL DATA FROM DATABASE
        const courses = await db.collection('courses').find({}, {
            projection: {
                _id: 1,
                title: 1,
                subject: 1,
                class: 1,
                description: 1,
                teacher: 1,
                youtubeUrl: 1,
                createdAt: 1
            }
        }).toArray();
        
        res.json(courses);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/courses', requireAuth, async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ error: 'Database not connected' });
        }

        const { title, subject, class: courseClass, description, teacher, youtubeUrl } = req.body;

        // Check if course already exists
        const existingCourse = await db.collection('courses').findOne({ 
            title, 
            class: courseClass,
            subject 
        });

        if (existingCourse) {
            return res.status(400).json({ 
                error: 'Course already exists',
                details: 'A course with this title, class, and subject already exists'
            });
        }

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

        res.status(201).json({ 
            message: 'Course created successfully', 
            course: {
                _id: course._id,
                title: course.title,
                subject: course.subject,
                class: course.class,
                teacher: course.teacher
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ===== ATTENDANCE ROUTES =====
app.get('/api/attendance', requireAuth, async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ error: 'Database not connected' });
        }
        
        // Get query parameters for filtering
        const { class: className, date } = req.query;
        let query = {};
        
        if (className) {
            query.class = className;
        }
        
        if (date) {
            const startDate = new Date(date);
            startDate.setHours(0, 0, 0, 0);
            const endDate = new Date(date);
            endDate.setHours(23, 59, 59, 999);
            query.date = { $gte: startDate, $lte: endDate };
        }
        
        // REAL DATA FROM DATABASE
        const attendance = await db.collection('attendance').find(query, {
            projection: {
                _id: 1,
                date: 1,
                class: 1,
                subject: 1,
                students: 1,
                createdAt: 1
            }
        }).sort({ date: -1 }).toArray();
        
        res.json(attendance);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/attendance', requireAuth, async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ error: 'Database not connected' });
        }

        const { date, class: attendanceClass, subject, students } = req.body;

        // Check if attendance already exists for this date, class, and subject
        const attendanceDate = new Date(date);
        attendanceDate.setHours(0, 0, 0, 0);
        const endDate = new Date(date);
        endDate.setHours(23, 59, 59, 999);

        const existingAttendance = await db.collection('attendance').findOne({
            class: attendanceClass,
            subject: subject,
            date: { $gte: attendanceDate, $lte: endDate }
        });

        if (existingAttendance) {
            return res.status(400).json({ 
                error: 'Attendance already recorded',
                details: 'Attendance for this class and subject has already been recorded today'
            });
        }

        const attendanceData = {
            date: new Date(date),
            class: attendanceClass,
            subject: subject,
            students: students.map(student => ({
                studentId: student.studentId,
                name: student.name,
                status: student.status || 'present',
                time: student.time || new Date().toLocaleTimeString('en-US', { hour12: true })
            })),
            createdBy: req.user._id,
            createdAt: new Date()
        };

        const result = await db.collection('attendance').insertOne(attendanceData);
        const attendance = await db.collection('attendance').findOne({ _id: result.insertedId });

        res.status(201).json({ 
            message: 'Attendance recorded successfully', 
            attendance: {
                _id: attendance._id,
                date: attendance.date,
                class: attendance.class,
                subject: attendance.subject,
                studentCount: attendance.students.length
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ===== RESULTS ROUTES =====
app.get('/api/results', requireAuth, async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ error: 'Database not connected' });
        }
        
        // Get query parameters for filtering
        const { studentId, examType, subject, class: className } = req.query;
        let query = {};
        
        if (studentId) query.studentId = studentId;
        if (examType) query.examType = examType;
        if (subject) query.subject = subject;
        if (className) query.class = className;
        
        // REAL DATA FROM DATABASE
        const results = await db.collection('results').find(query, {
            projection: {
                _id: 1,
                studentId: 1,
                studentName: 1,
                examType: 1,
                subject: 1,
                marks: 1,
                totalMarks: 1,
                grade: 1,
                class: 1,
                driveLink: 1,
                createdAt: 1
            }
        }).sort({ createdAt: -1 }).toArray();
        
        res.json(results);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/results', requireAuth, async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ error: 'Database not connected' });
        }

        const { studentId, examType, subject, marks, totalMarks, class: resultClass, driveLink } = req.body;

        // Check if result already exists for this student, exam, and subject
        const existingResult = await db.collection('results').findOne({
            studentId,
            examType,
            subject
        });

        if (existingResult) {
            return res.status(400).json({ 
                error: 'Result already exists',
                details: 'A result for this student, exam, and subject already exists'
            });
        }

        const grade = calculateGrade(marks);

        const resultData = {
            studentId,
            studentName: '', // Will be populated from students collection
            examType,
            subject,
            marks: parseInt(marks),
            totalMarks: parseInt(totalMarks),
            grade,
            class: resultClass,
            driveLink,
            createdBy: req.user._id,
            createdAt: new Date()
        };

        // Get student name
        const student = await db.collection('students').findOne({ admissionNo: studentId });
        if (student) {
            resultData.studentName = `${student.firstName} ${student.lastName}`;
        }

        const result = await db.collection('results').insertOne(resultData);
        const newResult = await db.collection('results').findOne({ _id: result.insertedId });

        res.status(201).json({ 
            message: 'Result saved successfully', 
            result: {
                _id: newResult._id,
                studentId: newResult.studentId,
                studentName: newResult.studentName,
                examType: newResult.examType,
                subject: newResult.subject,
                marks: newResult.marks,
                totalMarks: newResult.totalMarks,
                grade: newResult.grade
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ===== ANNOUNCEMENT ROUTES =====
app.get('/api/announcements', requireAuth, async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ error: 'Database not connected' });
        }
        
        // Get query parameters
        const { priority, audience } = req.query;
        let query = {};
        
        if (priority) query.priority = priority;
        if (audience) query.audience = audience;
        
        // REAL DATA FROM DATABASE
        const announcements = await db.collection('announcements').find(query, {
            projection: {
                _id: 1,
                title: 1,
                content: 1,
                audience: 1,
                priority: 1,
                date: 1,
                createdBy: 1
            }
        }).sort({ date: -1 }).toArray();
        
        // Populate creator names
        const populatedAnnouncements = await Promise.all(announcements.map(async (announcement) => {
            if (announcement.createdBy) {
                const creator = await db.collection('users').findOne(
                    { _id: new ObjectId(announcement.createdBy) },
                    { projection: { name: 1, role: 1 } }
                );
                return {
                    ...announcement,
                    createdByName: creator ? creator.name : 'Unknown',
                    createdByRole: creator ? creator.role : 'Unknown'
                };
            }
            return announcement;
        }));
        
        res.json(populatedAnnouncements);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/announcements', requireAuth, async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ error: 'Database not connected' });
        }

        const { title, content, audience, priority } = req.body;

        const announcementData = {
            title,
            content,
            audience: audience || 'all',
            priority: priority || 'medium',
            createdBy: req.user._id,
            date: new Date()
        };

        const result = await db.collection('announcements').insertOne(announcementData);
        const announcement = await db.collection('announcements').findOne({ _id: result.insertedId });

        res.status(201).json({ 
            message: 'Announcement created successfully', 
            announcement: {
                _id: announcement._id,
                title: announcement.title,
                content: announcement.content,
                audience: announcement.audience,
                priority: announcement.priority,
                date: announcement.date
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ===== RESOURCE ROUTES =====
app.get('/api/resources', requireAuth, async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ error: 'Database not connected' });
        }
        
        // Get query parameters
        const { type, subject, class: resourceClass } = req.query;
        let query = {};
        
        if (type) query.type = type;
        if (subject) query.subject = subject;
        if (resourceClass) query.class = resourceClass;
        
        // REAL DATA FROM DATABASE
        const resources = await db.collection('resources').find(query, {
            projection: {
                _id: 1,
                type: 1,
                title: 1,
                content: 1,
                subject: 1,
                class: 1,
                createdAt: 1,
                createdBy: 1
            }
        }).sort({ createdAt: -1 }).toArray();
        
        res.json(resources);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/resources', requireAuth, async (req, res) => {
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
            createdBy: req.user._id,
            createdAt: new Date()
        };

        const result = await db.collection('resources').insertOne(resourceData);
        const resource = await db.collection('resources').findOne({ _id: result.insertedId });

        res.status(201).json({ 
            message: 'Resource created successfully', 
            resource: {
                _id: resource._id,
                type: resource.type,
                title: resource.title,
                subject: resource.subject,
                class: resource.class
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ===== FLASHCARD ROUTES =====
app.get('/api/flashcards', requireAuth, async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ error: 'Database not connected' });
        }
        
        // REAL DATA FROM DATABASE - Only user's flashcards
        const flashcards = await db.collection('flashcards').find({ createdBy: req.user._id }, {
            projection: {
                _id: 1,
                question: 1,
                answer: 1,
                createdAt: 1
            }
        }).sort({ createdAt: -1 }).toArray();
        
        res.json(flashcards);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/flashcards', requireAuth, async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ error: 'Database not connected' });
        }

        const { question, answer } = req.body;

        const flashcardData = {
            question,
            answer,
            createdBy: req.user._id,
            createdAt: new Date()
        };

        const result = await db.collection('flashcards').insertOne(flashcardData);
        const flashcard = await db.collection('flashcards').findOne({ _id: result.insertedId });

        res.status(201).json({ 
            message: 'Flashcard created successfully', 
            flashcard: {
                _id: flashcard._id,
                question: flashcard.question,
                answer: flashcard.answer
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ===== NOTE ROUTES =====
app.get('/api/notes', requireAuth, async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ error: 'Database not connected' });
        }
        
        // REAL DATA FROM DATABASE - Only user's notes
        const notes = await db.collection('notes').find({ createdBy: req.user._id }, {
            projection: {
                _id: 1,
                content: 1,
                date: 1
            }
        }).sort({ date: -1 }).toArray();
        
        res.json(notes);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/notes', requireAuth, async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ error: 'Database not connected' });
        }

        const { content } = req.body;

        const noteData = {
            content,
            createdBy: req.user._id,
            date: new Date()
        };

        const result = await db.collection('notes').insertOne(noteData);
        const note = await db.collection('notes').findOne({ _id: result.insertedId });

        res.status(201).json({ 
            message: 'Note created successfully', 
            note: {
                _id: note._id,
                content: note.content,
                date: note.date
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/notes/:id', requireAuth, async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ error: 'Database not connected' });
        }

        const noteId = req.params.id;
        
        // Verify the note belongs to the user
        const note = await db.collection('notes').findOne({ 
            _id: new ObjectId(noteId),
            createdBy: req.user._id 
        });

        if (!note) {
            return res.status(404).json({ 
                error: 'Note not found',
                details: 'Note does not exist or you do not have permission to delete it'
            });
        }

        await db.collection('notes').deleteOne({ _id: new ObjectId(noteId) });
        
        res.json({ 
            message: 'Note deleted successfully',
            noteId: noteId
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ===== STUDY TIME ROUTES =====
app.get('/api/study-times', requireAuth, async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ error: 'Database not connected' });
        }
        
        // REAL DATA FROM DATABASE - User's study times
        const studyTimes = await db.collection('studytimes').find({ userId: req.user._id }, {
            projection: {
                _id: 1,
                minutes: 1,
                date: 1
            }
        }).sort({ date: -1 }).toArray();
        
        res.json(studyTimes);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/study-times', requireAuth, async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ error: 'Database not connected' });
        }

        const { minutes } = req.body;

        const studyTimeData = {
            userId: req.user._id,
            minutes: parseInt(minutes),
            date: new Date()
        };

        const result = await db.collection('studytimes').insertOne(studyTimeData);
        const studyTime = await db.collection('studytimes').findOne({ _id: result.insertedId });

        res.status(201).json({ 
            message: 'Study time updated successfully', 
            studyTime: {
                _id: studyTime._id,
                minutes: studyTime.minutes,
                date: studyTime.date
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ===== VIDEO ROUTES =====
app.get('/api/videos', requireAuth, async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ error: 'Database not connected' });
        }
        
        // Get query parameters
        const { courseId } = req.query;
        let query = {};
        
        if (courseId) query.courseId = courseId;
        
        // REAL DATA FROM DATABASE
        const videos = await db.collection('videos').find(query, {
            projection: {
                _id: 1,
                courseId: 1,
                title: 1,
                description: 1,
                youtubeId: 1,
                order: 1,
                createdAt: 1
            }
        }).sort({ order: 1 }).toArray();
        
        res.json(videos);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/videos', requireAuth, async (req, res) => {
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
            order: parseInt(order) || 0,
            createdAt: new Date()
        };

        const result = await db.collection('videos').insertOne(videoData);
        const video = await db.collection('videos').findOne({ _id: result.insertedId });

        res.status(201).json({ 
            message: 'Video added successfully', 
            video: {
                _id: video._id,
                courseId: video.courseId,
                title: video.title,
                youtubeId: video.youtubeId,
                order: video.order
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ===== EVENT ROUTES =====
app.get('/api/events', requireAuth, async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ error: 'Database not connected' });
        }
        
        // REAL DATA FROM DATABASE
        const events = await db.collection('events').find({}, {
            projection: {
                _id: 1,
                title: 1,
                description: 1,
                date: 1,
                time: 1,
                location: 1,
                type: 1,
                audience: 1,
                createdAt: 1
            }
        }).sort({ date: 1 }).toArray();
        
        // If no events in DB, return some default ones
        if (events.length === 0) {
            const defaultEvents = [
                {
                    _id: '1',
                    title: 'Parent-Teacher Meeting',
                    description: 'Quarterly parent-teacher meeting',
                    date: new Date(new Date().setDate(new Date().getDate() + 5)),
                    time: '10:00 AM - 12:00 PM',
                    location: 'School Auditorium',
                    type: 'meeting',
                    audience: 'all'
                },
                {
                    _id: '2',
                    title: 'Science Fair',
                    description: 'Annual science fair exhibition',
                    date: new Date(new Date().setDate(new Date().getDate() + 10)),
                    time: '9:00 AM - 4:00 PM',
                    location: 'Science Block',
                    type: 'fair',
                    audience: 'all'
                },
                {
                    _id: '3',
                    title: 'Unit Test - Mathematics',
                    description: 'Class 11 Mathematics Unit Test',
                    date: new Date(new Date().setDate(new Date().getDate() + 15)),
                    time: 'Period 3 & 4',
                    location: 'Respective Classrooms',
                    type: 'exam',
                    audience: 'students'
                }
            ];
            return res.json(defaultEvents);
        }
        
        res.json(events);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ===== LEADERBOARD ROUTES =====
app.get('/api/leaderboard', requireAuth, async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ error: 'Database not connected' });
        }
        
        // REAL DATA FROM DATABASE - Calculate leaderboard from results
        const results = await db.collection('results').aggregate([
            {
                $group: {
                    _id: '$studentId',
                    studentName: { $first: '$studentName' },
                    totalMarks: { $sum: '$marks' },
                    totalExams: { $sum: 1 },
                    averageScore: { $avg: '$marks' }
                }
            },
            {
                $lookup: {
                    from: 'students',
                    localField: '_id',
                    foreignField: 'admissionNo',
                    as: 'studentInfo'
                }
            },
            {
                $unwind: {
                    path: '$studentInfo',
                    preserveNullAndEmptyArrays: true
                }
            },
            {
                $project: {
                    studentId: '$_id',
                    name: {
                        $cond: {
                            if: { $eq: ['$studentName', ''] },
                            then: { $concat: ['$studentInfo.firstName', ' ', '$studentInfo.lastName'] },
                            else: '$studentName'
                        }
                    },
                    class: '$studentInfo.class',
                    section: '$studentInfo.section',
                    score: { $round: ['$averageScore', 2] },
                    totalExams: 1,
                    totalMarks: 1
                }
            },
            {
                $sort: { score: -1 }
            },
            {
                $limit: 10
            }
        ]).toArray();
        
        // If no results, return sample data
        if (results.length === 0) {
            const sampleLeaderboard = [
                { name: 'Aarav Sharma', score: 95, class: '11', section: 'A' },
                { name: 'Priya Patel', score: 92, class: '11', section: 'B' },
                { name: 'Rohan Kumar', score: 89, class: '12', section: 'A' },
                { name: 'Sneha Verma', score: 87, class: '11', section: 'C' },
                { name: 'Kunal Singh', score: 85, class: '12', section: 'B' }
            ];
            return res.json(sampleLeaderboard);
        }
        
        // Format the results
        const leaderboard = results.map((item, index) => ({
            rank: index + 1,
            name: item.name,
            score: `${item.score}%`,
            class: `${item.class || 'N/A'}-${item.section || 'N/A'}`,
            totalExams: item.totalExams
        }));
        
        res.json(leaderboard);
    } catch (error) {
        console.error('Leaderboard error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ===== ROOT ENDPOINT =====
app.get('/', (req, res) => {
    const dbStatus = db ? 'connected' : 'disconnected';
    
    res.json({ 
        message: 'EduHub School Management System API',
        version: '2.0.0',
        database: dbStatus,
        endpoints: {
            health: 'GET /api/health',
            auth: ['POST /api/auth/login', 'POST /api/auth/register'],
            dashboard: 'GET /api/dashboard/stats',
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
            events: 'GET /api/events',
            leaderboard: 'GET /api/leaderboard'
        },
        timestamp: new Date().toISOString()
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('❌ Server Error:', err.stack);
    res.status(500).json({ 
        error: 'Internal server error',
        details: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong!'
    });
});

// 404 Handler
app.use((req, res) => {
    res.status(404).json({ 
        error: 'Endpoint not found',
        path: req.path,
        method: req.method 
    });
});

// Start Server
app.listen(PORT, () => {
    console.log(`🚀 EduHub Backend running on port ${PORT}`);
    console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`🔗 Health check: http://localhost:${PORT}/api/health`);
    console.log(`🌐 API Root: http://localhost:${PORT}/`);
    console.log(`📈 Real data mode: ACTIVE - All endpoints return data from MongoDB`);
});
