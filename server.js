import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import cors from 'cors';
import multer from 'multer';
import { v2 as cloudinary } from 'cloudinary';
import fs from 'fs';
import nodemailer from 'nodemailer';
import { createClient } from '@supabase/supabase-js';
import { differenceInDays, parseISO } from 'date-fns';
import twilio from 'twilio';

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

const PORT = process.env.PORT || 3000;

// Supabase Setup
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);

// Cloudinary Config
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const upload = multer({ dest: '/tmp' });

// Nodemailer Config
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// JWT Token Generator
const generateToken = (user) =>
  jwt.sign(
    { id: user.id, email: user.email, name: user.name, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );

const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Missing or invalid auth token' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token invalid or expired' });
    req.user = user;
    next();
  });
};

const uploadImage = async (file) => {
  if (!file) return null;
  const result = await cloudinary.uploader.upload(file.path, { folder: 'SPACE_G' });
  fs.unlinkSync(file.path);
  return result.secure_url;
};

// Routes
app.get('/', (req, res) => {
  res.send('WELCOME TO TERRA GUARD API');
});


// Register
app.post('/register', upload.single('image'), async (req, res) => {
  const { email, password, name, phoneNumber, location, role = 'customer' } = req.body;
  if (!email || !password || !name || !location)
    return res.status(400).json({ error: 'All fields are required' });

  try {
    const { data: exists } = await supabase
      .from('users')
      .select('*')
      .eq('email', email)
      .single();

    if (exists) return res.status(400).json({ error: 'Email already registered' });

    const hashed = await bcrypt.hash(password, 10);
    const imageUrl = req.file ? await uploadImage(req.file) : null;

    const { data: user, error } = await supabase
      .from('users')
      .insert({
        email,
        password: hashed,
        name,
        profile_image_url: imageUrl,
        phone_number: phoneNumber,
        role,
        location,
      })
      .select()
      .single();

    if (error) throw error;

    res.status(201).json({ message: 'Registered successfully', token: generateToken(user), user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Login
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const { data: user } = await supabase
      .from('users')
      .select('*')
      .eq('email', email)
      .single();

    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(400).json({ error: 'Invalid credentials' });

    res.json({ token: generateToken(user), user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get Profile
app.get('/auth/profile', authenticateToken, async (req, res) => {
  try {
    const { data: user } = await supabase
      .from('users')
      .select('*')
      .eq('id', req.user.id)
      .single();

    if (!user) return res.status(404).json({ error: 'User not found' });

    res.json(user);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Update Profile
app.put('/auth/profile', authenticateToken, upload.single('image'), async (req, res) => {
  try {
    const { name, email, phoneNumber } = req.body;
    const updates = {};
    if (name) updates.name = name;
    if (email) updates.email = email;
    if (phoneNumber) updates.phone_number = phoneNumber;
    if (req.file) updates.profile_image_url = await uploadImage(req.file);

    if (!Object.keys(updates).length)
      return res.status(400).json({ error: 'No updates provided' });

    const { data: updatedUser, error } = await supabase
      .from('users')
      .update(updates)
      .eq('id', req.user.id)
      .select()
      .single();

    if (error) throw error;

    res.json(updatedUser);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Forgot Password (Sends Email)
app.post('/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  try {
    const { data: user } = await supabase
      .from('users')
      .select('*')
      .eq('email', email)
      .single();

    if (!user) return res.status(404).json({ error: 'User not found' });

    const resetToken = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '15m' });
    const resetUrl = `https://localhost:3000/reset-password?token=${resetToken}`;

    await transporter.sendMail({
      from: `"TERRA GUARD" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Password Reset',
      html: `<p>Reset your password:</p><a href="${resetUrl}">${resetUrl}</a>`,
    });

    res.json({ message: 'Reset link sent if user exists' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Reset Password
app.post('/auth/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;
  try {
    const { userId } = jwt.verify(token, process.env.JWT_SECRET);
    const hashed = await bcrypt.hash(newPassword, 10);

    const { error } = await supabase
      .from('users')
      .update({ password: hashed })
      .eq('id', userId);

    if (error) throw error;

    res.json({ message: 'Password reset successful' });
  } catch {
    res.status(400).json({ error: 'Invalid or expired token' });
  }
});

// SMS SENDING

// Twilio Config
const twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
const twilioNumber = process.env.TWILIO_PHONE_NUMBER;

// Notify Users Based on Location, Percentage, Date
app.post('/alerts/notify-users', async (req, res) => {
  const { location, percentage, date } = req.body;

  if (!location || !percentage || !date)
    return res.status(400).json({ error: 'Location, percentage, and date are required' });

  const targetDate = parseISO(date);
  const today = new Date();
  const daysAhead = differenceInDays(targetDate, today);

  if (daysAhead < 1 || daysAhead > 7)
    return res.status(400).json({ error: 'Date must be between 1–7 days ahead' });

  if (percentage < 60 || percentage > 100)
    return res.status(400).json({ error: 'Percentage must be between 60–100' });

  try {
    const { data: users, error } = await supabase
      .from('users')
      .select('phone_number')
      .ilike('location', `%${location}%`);

    if (error) throw error;

    if (!users || users.length === 0)
      return res.status(404).json({ message: 'No users found for this location' });

    const alertMessage = `Flood Alert: ${percentage}% chance of flooding expected in ${location} between now and ${date}. Please stay alert and safe!`;

    for (const user of users) {
      if (!user.phone_number) continue;
      try {
        await twilioClient.messages.create({
          body: alertMessage,
          from: twilioNumber,
          to: user.phone_number,
        });
      } catch (smsError) {
        console.error(`Failed to send SMS to ${user.phone_number}: ${smsError.message}`);
      }
    }

    res.json({ message: 'SMS alerts sent successfully', usersNotified: users.length });

  } catch (err) {
    console.error('Notify Error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// REPORT

app.post('/reports', authenticateToken, upload.single('image'), async (req, res) => {
  const { disaster_type, title, description, location, contact_info } = req.body;
  const userId = req.user.id;

  // Basic validation
  if (!disaster_type || !title || !description || !location) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  try {
    let imageUrl = null;
    if (req.file) {
      imageUrl = await uploadImage(req.file);
    }

    const { data: report, error } = await supabase
      .from('reports')
      .insert([
        {
          user_id: userId,
          disaster_type,
          title,
          description,
          location,
          contact_info,
          image_url: imageUrl,
        },
      ])
      .select()
      .single();

    if (error) throw error;

    res.status(201).json({ message: 'Report submitted successfully', report });
  } catch (err) {
    console.error('Submit Report Error:', err.message);
    res.status(500).json({ error: 'Failed to submit report' });
  }
});

//ADMIN ROUTES
// GET ALL REPORTS
app.get('/admin/reports', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied' });
  }

  try {
    const { data: reports, error } = await supabase
      .from('reports')
      .select('*')
      .order('created_at', { ascending: false });

    if (error) throw error;

    res.json(reports);
  } catch (err) {
    console.error('Fetch Reports Error:', err.message);
    res.status(500).json({ error: 'Failed to fetch reports' });
  }
});

// GET ALL USERS
app.get('/admin/users', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied' });
  }

  try {
    const { data: users, error } = await supabase
      .from('users')
      .select('*')
      .order('created_at', { ascending: false });

    if (error) throw error;

    res.json(users);
  } catch (err) {
    console.error('Fetch Users Error:', err.message);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});



app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
