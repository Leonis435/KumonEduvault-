// ========== General imports & setup ==========
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const multer = require('multer');
const NodeClam = require('clamscan');
const fs = require('fs');

const Admin = require('./models/Admin');
const Instructor = require('./models/Instructor');
const Student = require('./models/Student');
const Notification = require('./models/Notification');
const File = require('./models/File');
const ActivityLog = require('./models/ActivityLog');
const Threat = require('./models/Threat');

const app = express();

// ========== File Threat Detection Setup ==========

let clamav = null;

(async () => {
  try {
    const clamscan = await new NodeClam().init({
      removeInfected: false,
      quarantineInfected: false,
      scanRecursively: true,
      debugMode: false,
      clamdscan: {
        socket: '/var/run/clamd.scan/clamd.sock', // Linux default
        host: '127.0.0.1',
        port: 3310,
        timeout: 60000,
      },
      preference: 'clamdscan',
    });
    clamav = clamscan;
    console.log('✅ File Threat Detection: ClamAV initialized and ready');
  } catch (err) {
    console.warn('⚠️ File Threat Detection running in fallback mode (ClamAV not found).');
  }
})();


// ===== Middleware =====
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: 'super-secret-session-key',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, secure: false, sameSite: 'lax', maxAge: 1000 * 60 * 60 * 2 }
}));

// ===== Small helpers =====
const getModelByRole = (role) => {
  if (!role) return null;
  switch (String(role).toLowerCase()) {
    case 'admin': return Admin;
    case 'instructor': return Instructor;
    case 'student': return Student;
    default: return null;
  }
};

// ===========================
// Helper: Log activity (auto-fix role casing)
// ===========================
async function logActivity({ userId, userRole, userEmail, action }) {
  try {
    const roleMap = {
      admin: 'Admin',
      instructor: 'Instructor',
      student: 'Student',
    };

    const log = new ActivityLog({
      userId,
      userRole: roleMap[userRole] || userRole,
      userEmail,
      action,
    });

    await log.save();
  } catch (err) {
    console.error('Error saving activity log:', err);
  }
}



// Escape regex helper for safe case-insensitive match
function escapeRegExp(string) {
  return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// ===== Activity log helper (keeps DB logging, minimal console output) =====
async function logActivity({ userId = null, userRole = 'system', userEmail = 'unknown', action = '' }) {
  try {
    await ActivityLog.create({ userId, userRole, userEmail, action });
  } catch (err) {
    console.error('Error saving activity log:', err);
  }
}

// ====== DATABASE ======
mongoose.connect(
  "mongodb+srv://lancemacalalad1104_db_user:OxUBj8xxF85JYKIA@cluster0.sxatxqn.mongodb.net/Users?retryWrites=true&w=majority",
  { useNewUrlParser: true, useUnifiedTopology: true }
)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  });

// ===== Multer (file upload) =====
const upload = multer({ storage: multer.memoryStorage() });

/* ============================================================
   General / Auth Routes (shared by Student, Instructor, Admin)
   ============================================================ */

// ============================
// ✅ SHARED SIGNUP ROUTE
// ============================
app.post('/signup', async (req, res) => {
  try {
    const { email = '', password = '', role = '', idnum, fullname, start, subject, subjects } = req.body;
    const emailTrim = String(email).trim();
    if (!emailTrim || !password)
      return res.status(400).json({ message: 'Email and password are required.' });
    if (password.length < 6)
      return res.status(400).json({ message: 'Password must be at least 6 characters.' });

    const Model = getModelByRole(role);
    if (!Model)
      return res.status(400).json({ message: 'Invalid role specified.' });

    // Check for existing user (case-insensitive)
    const existing = await Model.findOne({
      email: { $regex: new RegExp(`^${escapeRegExp(emailTrim)}$`, 'i') },
    });
    if (existing)
      return res.status(400).json({ message: 'Email already exists.' });

    const hashedPassword = await bcrypt.hash(password, 10);
    let newUser;

    // Normalize role (capitalize first letter)
    const roleProper = String(role).charAt(0).toUpperCase() + String(role).slice(1).toLowerCase();

    if (roleProper === 'Admin') {
      if (!idnum || !fullname || !start)
        return res.status(400).json({ message: 'ID, name, and start date are required.' });
      newUser = new Model({
        email: emailTrim,
        password: hashedPassword,
        idNumber: idnum,
        fullName: fullname,
        startingDate: new Date(start),
        role: roleProper,
      });
    } else if (roleProper === 'Instructor') {
      if (!idnum || !fullname || !start || !subject)
        return res.status(400).json({ message: 'Missing instructor data.' });
      if (!['Math', 'Reading'].includes(subject))
        return res.status(400).json({ message: 'Subject must be Math or Reading.' });
      newUser = new Model({
        email: emailTrim,
        password: hashedPassword,
        idNumber: idnum,
        fullName: fullname,
        startingDate: new Date(start),
        role: roleProper,
        subject,
      });
    } else if (roleProper === 'Student') {
      if (!fullname || !subjects)
        return res.status(400).json({ message: 'Full name and subjects are required.' });
      if (!['Math', 'Reading', 'Both'].includes(subjects))
        return res.status(400).json({ message: 'Invalid subjects.' });
      newUser = new Model({
        email: emailTrim,
        password: hashedPassword,
        name: fullname,
        role: roleProper,
        subjects,
      });
    } else {
      return res.status(400).json({ message: 'Invalid role specified.' });
    }

    await newUser.save();

    // ✅ Log Activity
    await logActivity({
      userId: newUser._id,
      userRole: roleProper,
      userEmail: emailTrim,
      action: `${roleProper} signed up`,
    });

    res.status(201).json({ message: `${roleProper} signup successful!` });
  } catch (err) {
    console.error('[SIGNUP ERROR]', err);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});


// ============================
// ✅ SHARED LOGIN ROUTE
// ============================
app.post('/login', async (req, res) => {
  try {
    const { email = '', password = '', role = '' } = req.body;
    const emailTrim = String(email).trim();
    if (!emailTrim || !password)
      return res.status(400).json({ message: 'Email and password are required.' });

    const Model = getModelByRole(role);
    if (!Model)
      return res.status(400).json({ message: 'Invalid role.' });

    const user = await Model.findOne({
      email: { $regex: new RegExp(`^${escapeRegExp(emailTrim)}$`, 'i') },
    });
    if (!user)
      return res.status(401).json({ message: 'Email not found.' });

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch)
      return res.status(401).json({ message: 'Incorrect password.' });

    const name = user.name || user.fullName || emailTrim.split('@')[0];
    const roleProper = String(role).charAt(0).toUpperCase() + String(role).slice(1).toLowerCase();

    // Store session
    req.session.user = {
      email: user.email,
      name,
      role: roleProper,
      id: user._id,
    };

    // ✅ Log Activity
    await logActivity({
      userId: user._id,
      userRole: roleProper,
      userEmail: user.email,
      action: `${roleProper} logged in`,
    });

    const responseData = {
      message: `${roleProper} login successful!`,
      email: user.email,
      name,
      role: roleProper,
      id: user._id,
    };

    if (roleProper === 'Instructor' && user.subject)
      responseData.subject = user.subject;

    res.json(responseData);
  } catch (err) {
    console.error('[LOGIN ERROR]', err);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});


// Session check & logout
app.get('/session-check', (req, res) => {
  req.session.user ? res.json({ loggedIn: true, user: req.session.user }) : res.status(401).json({ loggedIn: false, message: 'No session' });
});

app.get('/api/logout', async (req, res) => {
  if (req.session?.user) {
    await logActivity({
      userId: req.session.user.id,
      userRole: req.session.user.role,
      userEmail: req.session.user.email,
      action: `${req.session.user.role} logged out`,
    });
    req.session.destroy(() => res.json({ message: 'Logged out.' }));
  } else {
    res.status(400).json({ message: 'No active session.' });
  }
});

/* ===========================
   Student-related endpoints
   =========================== */

// Get students by subject
app.get('/students/:subject', async (req, res) => {
  try {
    const { subject } = req.params;
    const allowed = ['Math', 'Reading', 'Both'];
    if (!allowed.includes(subject)) return res.status(400).json({ message: 'Invalid subject' });
    const criteria = subject === 'Both' ? {} : { $or: [{ subjects: subject }, { subjects: 'Both' }] };
    const students = await Student.find(criteria).select('-password').lean();
    res.json(students);
  } catch (err) {
    console.error('[GET STUDENTS]', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get student by email (case-insensitive)
app.get('/student/:email', async (req, res) => {
  try {
    const email = String(req.params.email).trim();
    const student = await Student.findOne({ email: { $regex: new RegExp(`^${escapeRegExp(email)}$`, 'i') } }).select('-password').lean();
    student ? res.json(student) : res.status(404).json({ message: 'Student not found' });
  } catch (err) {
    console.error('[GET STUDENT]', err);
    res.status(500).json({ message: 'Server error' });
  }
});

/* ===========================
   Instructor-related endpoints
   =========================== */

// Get instructor profile (protected)
app.get('/api/instructor/profile', async (req, res) => {
  try {
    if (!req.session?.user || req.session.user.role !== 'Instructor')
      return res.status(401).json({ message: 'Not authorized' });
    const instructor = await Instructor.findById(req.session.user.id).select('-password').lean();
    if (!instructor) return res.status(404).json({ message: 'Instructor not found' });
    res.json(instructor);
  } catch (err) {
    console.error('[PROFILE ERROR]', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get all instructors (public)
app.get('/instructors', async (req, res) => {
  try {
    const instructors = await Instructor.find().select('_id fullName email subject startingDate').lean();
    res.json(instructors);
  } catch (err) {
    console.error('[GET INSTRUCTORS]', err);
    res.status(500).json({ message: 'Failed to load instructors.' });
  }
});

// Get instructors by subject
app.get('/instructors/:subject', async (req, res) => {
  try {
    const { subject } = req.params;
    const allowed = ['Math', 'Reading', 'Both'];
    if (!allowed.includes(subject)) return res.status(400).json({ message: 'Invalid subject' });
    const filter = subject === 'Both' ? {} : { subject };
    res.json(await Instructor.find(filter).select('_id fullName email subject startingDate').lean());
  } catch (err) {
    console.error('[GET INSTRUCTORS BY SUBJECT]', err);
    res.status(500).json({ message: 'Server error' });
  }
});

/* ===========================
   File & instructor submission endpoints
   =========================== */

// Upload (general upload endpoint used by forms)
app.post('/upload', upload.single('file'), async (req, res) => {
  try {
    const { fileName, worksheetValue, instructor, email } = req.body;
    if (!req.file)
      return res.status(400).json({ success: false, message: 'No file uploaded.' });

    // convenience values
    const uploaderEmail = email || (req.session?.user?.email ?? 'unknown');
    const uploaderId = req.session?.user?.id ?? null;
    const uploaderRole = req.session?.user?.role ?? 'system';

    // 🧠 STEP 1: Virus scan before saving
    if (clamav) {
      try {
        const { isInfected, viruses } = await clamav.scanBuffer(req.file.buffer);

        if (isInfected) {
          console.warn(`🚨 Infected file detected: ${viruses.join(', ')}`);

          // 1) Save threat record to DB (for admin UI / audit)
          try {
            await Threat.create({
              fileName: req.file.originalname || fileName || 'unknown',
              uploaderEmail,
              detectedViruses: viruses,
              detectedAt: new Date(),
              status: 'blocked'
            });
          } catch (thErr) {
            console.error('Error saving Threat record:', thErr);
            // continue — we still want to block upload even if Threat save fails
          }

          // 2) Activity log entry
          await logActivity({
            userId: uploaderId,
            userRole: uploaderRole,
            userEmail: uploaderEmail,
            action: `⚠️ File upload blocked - Virus detected: ${viruses.join(', ')}`,
          });

          // 3) Respond to uploader (do NOT save file)
          return res.status(400).json({
            success: false,
            message: `File rejected due to virus: ${viruses.join(', ')}`,
          });
        }

        // OPTIONAL: If you want to record successful scan metadata in Threat (or a separate collection),
        // you could add a 'scan log' here. Not required.
      } catch (scanErr) {
        console.error('⚠️ Virus scan error:', scanErr);
        return res.status(500).json({
          success: false,
          message: 'Error scanning file for threats.',
        });
      }
    } else {
      console.warn('⚠️ ClamAV not initialized — skipping virus scan.');
      // Optionally record that scan was skipped (for audits) — up to you.
    }

    // ✅ STEP 2: Continue if file is safe
    let instructorDoc = null;
    if (instructor) {
      instructorDoc = await Instructor.findById(instructor);
      if (!instructorDoc)
        return res.status(400).json({ success: false, message: 'Invalid instructor ID.' });
    }

    const newFile = new File({
      fileName,
      worksheetValue,
      contentType: req.file.mimetype,
      data: req.file.buffer,
      instructor: instructorDoc ? instructorDoc._id : null,
      uploaderEmail,
      uploadedAt: new Date(),
    });

    await newFile.save();

    await logActivity({
      userId: uploaderId,
      userRole: uploaderRole,
      userEmail: uploaderEmail,
      action: `File uploaded: ${fileName}`,
    });

    res.json({ success: true, message: 'File uploaded successfully to MongoDB!' });
  } catch (err) {
    console.error('[UPLOAD ERROR]', err);
    res.status(500).json({ success: false, message: 'Server error while uploading.' });
  }
});



// Fetch all files
app.get('/files', async (req, res) => {
  try {
    const files = await File.find().populate('instructor', 'fullName subject').sort({ uploadedAt: -1 }).lean();
    const formatted = files.map(file => ({
      _id: file._id,
      fileName: file.fileName,
      worksheetValue: file.worksheetValue,
      fileData: file.data?.toString('base64'),
      contentType: file.contentType,
      uploaderEmail: file.uploaderEmail,
      instructor: file.instructor,
      uploadedAt: file.uploadedAt,
    }));
    res.json(formatted);
  } catch (err) {
    console.error('[FETCH FILES ERROR]', err);
    res.status(500).json({ message: 'Error fetching files' });
  }
});

// Download file by ID
app.get('/files/:id', async (req, res) => {
  try {
    const file = await File.findById(req.params.id);
    if (!file) return res.status(404).json({ message: 'File not found.' });
    res.set('Content-Type', file.contentType);
    res.set('Content-Disposition', `attachment; filename="${file.fileName}"`);
    res.send(file.data);
  } catch (err) {
    console.error('[DOWNLOAD FILE ERROR]', err);
    res.status(500).json({ message: 'Server error.' });
  }
});

// Instructor: get submissions linked to them
app.get('/api/instructor/:id/submissions', async (req, res) => {
  try {
    const instructorId = req.params.id;
    const files = await File.find({ instructor: instructorId }).populate('instructor', 'fullName email subject').lean();
    const formattedFiles = files.map(file => ({
      _id: file._id,
      fileName: file.fileName,
      worksheetValue: file.worksheetValue,
      uploaderEmail: file.uploaderEmail,
      uploadedAt: file.uploadedAt,
      contentType: file.contentType,
      base64Data: file.data?.toString('base64'),
      instructor: file.instructor ? {
        fullName: file.instructor.fullName,
        email: file.instructor.email,
        subject: file.instructor.subject
      } : null
    }));
    res.json(formattedFiles);
  } catch (err) {
    console.error('[INSTRUCTOR SUBMISSIONS FETCH ERROR]', err);
    res.status(500).json({ message: 'Error loading submissions', error: err.message });
  }
});

// Instructor: update a submission (edit name/remarks)
app.put('/api/instructor/submissions/:fileId', async (req, res) => {
  try {
    const { fileId } = req.params;
    const { fileName, remarks } = req.body;
    const updated = await File.findByIdAndUpdate(fileId, { fileName, notes: remarks }, { new: true });
    if (!updated) return res.status(404).json({ message: 'File not found' });

    await logActivity({
      userId: req.session?.user?.id ?? null,
      userRole: req.session?.user?.role ?? 'system',
      userEmail: req.session?.user?.email ?? 'unknown',
      action: `File updated: ${updated.fileName || 'Unnamed File'}`,
    });

    res.json({ message: 'File updated successfully', file: updated });
  } catch (err) {
    console.error('[UPDATE SUBMISSION ERROR]', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Instructor: delete submission
app.delete('/api/instructor/submissions/:fileId', async (req, res) => {
  try {
    const { fileId } = req.params;
    const deleted = await File.findByIdAndDelete(fileId);
    if (!deleted) return res.status(404).json({ message: 'File not found' });

    await logActivity({
      userId: req.session?.user?.id ?? null,
      userRole: req.session?.user?.role ?? 'system',
      userEmail: req.session?.user?.email ?? 'unknown',
      action: `File deleted: ${deleted.fileName || 'Unnamed File'}`,
    });

    res.json({ message: 'File deleted successfully' });
  } catch (err) {
    console.error('[DELETE SUBMISSION ERROR]', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Instructor-specific upload to student (instructor must be authenticated)
app.post('/instructor/upload', upload.single('file'), async (req, res) => {
  try {
    // ✅ Ensure only instructors can upload
    if (!req.session?.user || req.session.user.role !== 'instructor')
      return res.status(403).json({ message: 'Unauthorized' });

    const { studentId, fileName, notes } = req.body;
    const file = req.file;

    if (!file || !studentId || !fileName)
      return res.status(400).json({ message: 'All fields are required.' });

    const uploaderEmail = req.session.user.email;
    const uploaderId = req.session.user.id;

    // 🧠 STEP 1: Virus scan before saving file
    if (clamav) {
      try {
        const { isInfected, viruses } = await clamav.scanBuffer(file.buffer);
        if (isInfected) {
          console.warn(`🚨 Infected file detected: ${viruses.join(', ')}`);

          // 1️⃣ Save a threat record for admin monitoring
          try {
            await Threat.create({
              fileName: file.originalname || fileName,
              uploaderEmail,
              detectedViruses: viruses,
              detectedAt: new Date(),
              status: 'blocked',
            });
          } catch (thErr) {
            console.error('Error saving Threat record:', thErr);
          }

          // 2️⃣ Log it in ActivityLog
          await logActivity({
            userId: uploaderId,
            userRole: 'instructor',
            userEmail: uploaderEmail,
            action: `⚠️ File upload blocked - Virus detected: ${viruses.join(', ')}`,
          });

          // 3️⃣ Reject the file upload
          return res.status(400).json({
            success: false,
            message: `File rejected due to virus: ${viruses.join(', ')}`,
          });
        }
      } catch (scanErr) {
        console.error('⚠️ Virus scan error:', scanErr.message);
        return res.status(500).json({
          success: false,
          message: 'Error scanning file for threats.',
        });
      }
    } else {
      console.warn('⚠️ ClamAV not initialized — skipping virus scan.');
    }

    // ✅ STEP 2: Continue if file is safe
    const newFile = new File({
      originalName: file.originalname,
      mimeType: file.mimetype,
      size: file.size,
      data: file.buffer,
      fileName,
      uploaderEmail,
      instructor: uploaderId,
      student: studentId,
      notes: notes || '',
      uploadedAt: new Date(),
    });

    await newFile.save();

    await logActivity({
      userId: uploaderId,
      userRole: 'instructor',
      userEmail: uploaderEmail,
      action: `Instructor uploaded file: ${fileName}`,
    });

    res.json({
      success: true,
      message: 'File uploaded and linked to student!',
      fileId: newFile._id,
    });
  } catch (err) {
    console.error('[INSTRUCTOR UPLOAD ERROR]', err);
    res.status(500).json({ message: 'File upload failed.', error: err.message });
  }
});



/* ===========================
   Notifications (shared)
   =========================== */

// Get instructor notifications
app.get('/notifications/:id/instructor', async (req, res) => {
  try {
    const notifications = await Notification.find({ recipient: req.params.id, recipientModel: 'Instructor' }).sort({ createdAt: -1 }).lean();
    res.json(notifications);
  } catch (err) {
    console.error('[GET INSTRUCTOR NOTIFICATIONS]', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get student notifications
app.get('/notifications/:id/student', async (req, res) => {
  try {
    const notifications = await Notification.find({ recipient: req.params.id, recipientModel: 'Student' }).sort({ createdAt: -1 }).lean();
    res.json(notifications);
  } catch (err) {
    console.error('[GET STUDENT NOTIFICATIONS]', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Mark notification read
app.patch('/notifications/:id/read', async (req, res) => {
  try {
    const notificationId = req.params.id;
    const notification = await Notification.findByIdAndUpdate(notificationId, { read: true }, { new: true });
    if (!notification) return res.status(404).json({ message: 'Notification not found' });
    res.json({ message: 'Notification marked as read' });
  } catch (err) {
    console.error('[PATCH NOTIFICATION READ]', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Send notifications
app.post('/notifications/send', async (req, res) => {
  try {
    const { senderId, senderModel, recipientType, recipientsIds, message, subject } = req.body;
    if (!senderId || !senderModel || !recipientType || !message) return res.status(400).json({ message: 'Missing fields' });

    let targets = [], modelName = '';
    if (recipientType === 'students') {
      modelName = 'Student';
      targets = Array.isArray(recipientsIds) && recipientsIds.length
        ? await Student.find({ _id: { $in: recipientsIds } }).select('_id').lean()
        : await Student.find({ $or: [{ subjects: subject }, { subjects: 'Both' }] }).select('_id').lean();
    } else if (recipientType === 'instructors') {
      modelName = 'Instructor';
      targets = Array.isArray(recipientsIds) && recipientsIds.length
        ? await Instructor.find({ _id: { $in: recipientsIds } }).select('_id').lean()
        : await Instructor.find().select('_id').lean();
    } else if (recipientType === 'admins') {
      modelName = 'Admin';
      targets = Array.isArray(recipientsIds) && recipientsIds.length
        ? await Admin.find({ _id: { $in: recipientsIds } }).select('_id').lean()
        : await Admin.find().select('_id').lean();
    } else {
      return res.status(400).json({ message: 'Invalid recipientType' });
    }

    const created = await Promise.all(targets.map(t => new Notification({
      recipient: t._id,
      recipientModel: modelName,
      sender: senderId,
      senderModel,
      message
    }).save()));

    res.json({ message: `Notifications created: ${created.length}`, createdCount: created.length });
  } catch (err) {
    console.error('[SEND NOTIFICATIONS]', err);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

/* ===========================
   Admin-related endpoints
   =========================== */

// Helper to find which model contains an id
async function findUserModelById(id) {
  if (!mongoose.Types.ObjectId.isValid(id)) return null;
  let doc = await Student.findById(id).select('-password').lean();
  if (doc) return { model: Student, doc, role: 'Student' };
  doc = await Instructor.findById(id).select('-password').lean();
  if (doc) return { model: Instructor, doc, role: 'Instructor' };
  doc = await Admin.findById(id).select('-password').lean();
  if (doc) return { model: Admin, doc, role: 'Admin' };
  return null;
}

// Get all users (combined) - admin only
app.get(['/admin/users', '/api/admin/users'], async (req, res) => {
  if (!req.session?.user || req.session.user.role?.toLowerCase() !== 'admin') {
    return res.status(403).json({ message: 'Access denied (not admin)' });
  }
  try {
    const students = await Student.find().select('-password').lean();
    const instructors = await Instructor.find().select('-password').lean();
    const admins = await Admin.find().select('-password').lean();

    const payload = [
      ...students.map(s => ({ _id: s._id, name: s.name, email: s.email, role: 'Student' })),
      ...instructors.map(i => ({ _id: i._id, name: i.fullName, email: i.email, role: 'Instructor' })),
      ...admins.map(a => ({ _id: a._id, name: a.fullName, email: a.email, role: 'Admin' }))
    ];

    res.json(payload);
  } catch (err) {
    console.error('[GET /admin/users] error:', err);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Create user (admin)
app.post('/admin/users', requireAdmin, async (req, res) => {
  try {
    const body = req.body;
    const role = (body.role || '').toLowerCase();
    const email = String(body.email || '').trim();
    const password = body.password || 'changeme123';
    if (!email || !role) return res.status(400).json({ message: 'email and role are required' });

    const hashed = await bcrypt.hash(password, 10);

    if (role === 'student') {
      const existing = await Student.findOne({ email: { $regex: new RegExp(`^${escapeRegExp(email)}$`, 'i') } });
      if (existing) return res.status(400).json({ message: 'Email already exists' });
      const s = new Student({ email, password: hashed, name: body.name || email, subjects: body.subjects || 'Math' });
      await s.save();
      return res.status(201).json({ message: 'Student created', user: { _id: s._id, email: s.email, name: s.name, role: 'Student' } });
    } else if (role === 'instructor') {
      const existing = await Instructor.findOne({ email: { $regex: new RegExp(`^${escapeRegExp(email)}$`, 'i') } });
      if (existing) return res.status(400).json({ message: 'Email already exists' });
      if (!body.idNumber || !body.subject) return res.status(400).json({ message: 'idNumber and subject required for instructor' });
      const i = new Instructor({ email, password: hashed, idNumber: body.idNumber, fullName: body.name || email, startingDate: body.startingDate ? new Date(body.startingDate) : new Date(), subject: body.subject });
      await i.save();
      return res.status(201).json({ message: 'Instructor created', user: { _id: i._id, email: i.email, name: i.fullName, role: 'Instructor' } });
    } else if (role === 'admin') {
      const existing = await Admin.findOne({ email: { $regex: new RegExp(`^${escapeRegExp(email)}$`, 'i') } });
      if (existing) return res.status(400).json({ message: 'Email already exists' });
      if (!body.idNumber) return res.status(400).json({ message: 'idNumber required for admin' });
      const a = new Admin({ email, password: hashed, idNumber: body.idNumber, fullName: body.name || email, startingDate: body.startingDate ? new Date(body.startingDate) : new Date() });
      await a.save();
      return res.status(201).json({ message: 'Admin created', user: { _id: a._id, email: a.email, name: a.fullName, role: 'Admin' } });
    } else {
      return res.status(400).json({ message: 'Invalid role' });
    }
  } catch (err) {
    console.error('[POST /admin/users]', err);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Update user (admin)
app.put('/admin/users/:id', requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const found = await findUserModelById(id);
    if (!found) return res.status(404).json({ message: 'User not found' });
    if (found.role === 'Admin') return res.status(403).json({ message: 'Editing other Admins is not allowed' });

    const body = req.body;
    if (found.role === 'Student') {
      await Student.findByIdAndUpdate(id, { name: body.name, email: body.email, subjects: body.subjects });
      await logActivity({ userId: req.session.user.id, userRole: req.session.user.role, userEmail: req.session.user.email, action: `Admin updated Student: ${body.name || found.doc.name}` });
      return res.json({ message: 'Student updated' });
    } else if (found.role === 'Instructor') {
      await Instructor.findByIdAndUpdate(id, { fullName: body.name, email: body.email, subject: body.subject, idNumber: body.idNumber });
      await logActivity({ userId: req.session.user.id, userRole: req.session.user.role, userEmail: req.session.user.email, action: `Admin updated Instructor: ${body.name || found.doc.fullName}` });
      return res.json({ message: 'Instructor updated' });
    }
    res.status(400).json({ message: 'Unhandled role' });
  } catch (err) {
    console.error('[PUT /admin/users/:id]', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Delete user (admin)
app.delete('/admin/users/:id', requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const found = await findUserModelById(id);
    if (!found) return res.status(404).json({ message: 'User not found' });
    if (found.role === 'Admin') return res.status(403).json({ message: 'Deleting Admin accounts is not allowed' });

    await found.model.findByIdAndDelete(id);
    await logActivity({ userId: req.session.user.id, userRole: req.session.user.role, userEmail: req.session.user.email, action: `Admin deleted ${found.role}: ${found.doc.email || ''}` });
    return res.json({ message: `${found.role} deleted` });
  } catch (err) {
    console.error('[DELETE /admin/users/:id]', err);
    res.status(500).json({ message: 'Server error' });
  }
});

/* ===========================
   Admin: Activity Logs
   =========================== */

// Middleware: Require Admin (JSON version)
function requireAdmin(req, res, next) {
  if (!req.session?.user || req.session.user.role?.toLowerCase() !== "admin") {
    return res.status(403).json({ message: "Access denied. Admins only." });
  }
  next();
}


// Log activity manually (for admin or system actions)
app.post('/api/logs', async (req, res) => {
  try {
    const { userId, userRole, userEmail, action } = req.body;
    if (!userId || !userRole || !action) {
      return res.status(400).json({ message: 'Missing required fields' });
    }

    const log = new ActivityLog({ userId, userRole, userEmail, action });
    await log.save();

    res.json({ message: 'Activity logged', log });
  } catch (err) {
    console.error('[POST /api/logs]', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Fetch all activity logs (Admin only)
app.get('/admin/logs', requireAdmin, async (req, res) => {
  try {
    const logs = await ActivityLog.find()
      .populate('userId', 'fullName email')
      .sort({ timestamp: -1 })
      .lean();

    res.json(logs);
  } catch (err) {
    console.error('[GET /api/admin/logs]', err);
    res.status(500).json({ message: 'Server error fetching logs' });
  }
});

/* ===========================
   🧠 Admin: View Threat Logs
   =========================== */
app.get('/admin/threats', requireAdmin, async (req, res) => {
  try {
    const threats = await Threat.find().sort({ detectedAt: -1 }).lean();
    res.json(threats);
  } catch (err) {
    console.error('[GET /admin/threats]', err);
    res.status(500).json({ message: 'Error fetching threats' });
  }
});

// ✅ Admin can mark a threat as resolved
app.patch('/admin/threats/:id/resolve', requireAdmin, async (req, res) => {
  try {
    const updated = await Threat.findByIdAndUpdate(
      req.params.id,
      { status: 'resolved' },
      { new: true }
    );
    if (!updated) return res.status(404).json({ message: 'Threat not found' });
    res.json({ message: 'Threat resolved', threat: updated });
  } catch (err) {
    console.error('[PATCH /admin/threats/:id/resolve]', err);
    res.status(500).json({ message: 'Error resolving threat' });
  }
});

/* =======================================================
   📂 ADMIN FILE MANAGEMENT (MongoDB-based)
   ======================================================= */

app.get("/admin/files", requireAdmin, async (req, res) => {
  try {
    const files = await File.find()
      .populate("instructor", "fullName email")
      .sort({ uploadedAt: -1 })
      .lean();

    const payload = files.map((f) => ({
      _id: f._id,
      fileName: f.fileName,
      worksheetValue: f.worksheetValue || "Untitled Worksheet",
      uploaderEmail: f.uploaderEmail || "Unknown",
      instructor: f.instructor ? f.instructor.fullName : "—",
      contentType: f.contentType,
      uploadedAt: f.uploadedAt,
    }));

    res.json(payload);
  } catch (err) {
    console.error("[GET /admin/files]", err);
    res.status(500).json({ message: "Server error fetching files" });
  }
});

// ✅ Serve file data directly from MongoDB (for preview/download)
app.get("/admin/files/:id", requireAdmin, async (req, res) => {
  try {
    const file = await File.findById(req.params.id);
    if (!file) return res.status(404).send("File not found");

    res.set("Content-Type", file.contentType);
    res.send(file.data);
  } catch (err) {
    console.error("[GET /admin/files/:id]", err);
    res.status(500).send("Server error fetching file");
  }
});

// ✅ Delete a file
app.delete("/admin/files/:id", requireAdmin, async (req, res) => {
  try {
    const file = await File.findById(req.params.id);
    if (!file) return res.status(404).json({ message: "File not found" });

    await File.findByIdAndDelete(req.params.id);

    // Log admin activity
    await ActivityLog.create({
      userId: req.session.user.id,
      userRole: "admin",
      userEmail: req.session.user.email,
      action: `Deleted file: ${file.fileName}`,
    });

    res.json({ message: "File deleted successfully" });
  } catch (err) {
    console.error("[DELETE /admin/files/:id]", err);
    res.status(500).json({ message: "Server error deleting file" });
  }
});

/* ===========================
   Static files and fallback
   =========================== */
app.use(express.static(path.join(__dirname, 'public')));

// Serve main app page for other non-API routes
app.get(/.*/, (req, res, next) => {
  if (req.path.startsWith('/api/') || req.path.startsWith('/admin/') || req.path.startsWith('/notifications') || req.path.startsWith('/files')) return next();
  res.sendFile(path.join(__dirname, 'public', 'Mainhomepage.html'));
});



/* ===========================
   Start server
   =========================== */
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
