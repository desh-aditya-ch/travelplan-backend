const express = require('express');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');
const PDFDocument = require('pdfkit');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
require('dotenv').config();

// Import database module
const { database, userDB, itineraryDB, validateAndConvertId } = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;

// Initialize database connection
async function initializeDatabase() {
  try {
    const mongoUri = process.env.MONGODB_URI;
    
    if (!mongoUri) {
      throw new Error('MONGODB_URI environment variable is not set. Please check your .env file.');
    }
    
    console.log('🔗 Connecting to MongoDB Atlas...');
    await database.connect(mongoUri);
    
    console.log(`
✅ CONNECTED TO MONGODB ATLAS
   • Database: Connected successfully
   • Collections: Users, Itineraries
   • Storage: Persistent cloud storage
    `);
  } catch (error) {
    console.error(`
❌ FAILED TO CONNECT TO DATABASE
   • Error: ${error.message}
   • Please check your MongoDB Atlas connection string
   • Ensure your IP is whitelisted in Atlas
   • Verify your database credentials
    `);
    process.exit(1);
  }
}

// Initialize database
initializeDatabase();

// Middleware
app.use(cors({
  origin: process.env.CLIENT_URL || 'http://localhost:3000',
  credentials: true
}));

app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Initialize Google Generative AI
let genAI;
try {
  if (!process.env.GEMINI_API_KEY) {
    throw new Error('GEMINI_API_KEY is not set in environment variables');
  }
  genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
  console.log('✅ Google Generative AI initialized successfully');
} catch (error) {
  console.error('❌ Failed to initialize Google Generative AI:', error.message);
  console.log('⚠️ AI features will use fallback mode');
}

// JWT Helper Functions
const JWT_SECRET = process.env.JWT_SECRET || process.env.SESSION_SECRET;
const JWT_EXPIRES_IN = '24h';

function generateToken(user) {
  return jwt.sign(
    { 
      userId: user._id, 
      username: user.username,
      email: user.email 
    }, 
    JWT_SECRET, 
    { expiresIn: JWT_EXPIRES_IN }
  );
}

function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (error) {
    console.log('Token verification failed:', error.message);
    return null;
  }
}

// Authentication middleware (JWT-based)
const requireAuth = (req, res, next) => {
  const token = req.cookies.authToken || req.headers.authorization?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ 
      success: false,
      error: 'Authentication required',
      message: 'Please log in to access this resource'
    });
  }
  
  const decoded = verifyToken(token);
  if (!decoded) {
    return res.status(401).json({ 
      success: false,
      error: 'Invalid or expired token',
      message: 'Please log in again'
    });
  }
  
  req.userId = decoded.userId;
  req.username = decoded.username;
  req.userEmail = decoded.email;
  next();
};

// Error handling middleware
const handleAsync = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

// Request logging middleware
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// ============================================================================
// AUTHENTICATION ROUTES (JWT-based)
// ============================================================================

// Register new user
app.post('/api/register', handleAsync(async (req, res) => {
  const { username, email, password, fullName } = req.body;
  
  console.log('📝 Registration attempt for:', email);
  
  // Basic validation
  if (!username || !email || !password || !fullName) {
    return res.status(400).json({ 
      success: false,
      error: 'Missing required fields',
      message: 'Username, email, password, and full name are required'
    });
  }
  
  if (password.length < 6) {
    return res.status(400).json({ 
      success: false,
      error: 'Password too short',
      message: 'Password must be at least 6 characters long'
    });
  }

  if (username.length < 3) {
    return res.status(400).json({ 
      success: false,
      error: 'Username too short',
      message: 'Username must be at least 3 characters long'
    });
  }
  
  try {
    const user = await userDB.createUser({ username, email, password, fullName });
    console.log('📝 User created successfully:', user._id);
    
    // Generate JWT token
    const token = generateToken(user);
    console.log('🔑 JWT token generated for new user');
    
    // Set token as HTTP-only cookie
    res.cookie('authToken', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    });
    
    res.status(201).json({
      success: true,
      message: 'Account created successfully! Welcome to AI Travel Planner!',
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        fullName: user.fullName,
        createdAt: user.createdAt
      },
      token: token // Also send token in response for debugging
    });
    
  } catch (error) {
    console.error('💥 Registration error:', error);
    res.status(400).json({
      success: false,
      error: error.message.includes('already') ? 'User already exists' : 'Registration failed',
      message: error.message
    });
  }
}));

// Login user
app.post('/api/login', handleAsync(async (req, res) => {
  const { email, password } = req.body;
  
  console.log('🔐 Login attempt for:', email);
  
  if (!email || !password) {
    return res.status(400).json({ 
      success: false,
      error: 'Missing credentials',
      message: 'Email and password are required'
    });
  }
  
  try {
    const user = await userDB.authenticateUser(email, password);
    console.log('🔐 User authenticated successfully:', user._id);
    
    // Generate JWT token
    const token = generateToken(user);
    console.log('🔑 JWT token generated for login');
    
    // Set token as HTTP-only cookie
    res.cookie('authToken', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    });
    
    res.json({
      success: true,
      message: 'Welcome back! Login successful.',
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        fullName: user.fullName,
        lastLogin: user.lastLogin,
        preferences: user.preferences
      },
      token: token // Also send token in response for debugging
    });
    
  } catch (error) {
    console.error('💥 Login error:', error);
    res.status(401).json({
      success: false,
      error: 'Authentication failed',
      message: error.message
    });
  }
}));

// Logout user
app.post('/api/logout', (req, res) => {
  console.log('👋 User logout requested');
  
  // Clear the auth token cookie
  res.clearCookie('authToken', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax'
  });
  
  res.json({ 
    success: true, 
    message: 'Logout successful. See you next time!'
  });
});

// Get current user
app.get('/api/user', requireAuth, handleAsync(async (req, res) => {
  console.log('👤 User info requested for:', req.username);
  
  try {
    const user = await userDB.getUserById(req.userId);
    console.log('✅ User found:', user.username);
    
    res.json({
      success: true,
      user
    });
  } catch (error) {
    console.error('💥 Error getting user:', error);
    res.status(404).json({
      success: false,
      error: 'User not found',
      message: error.message
    });
  }
}));

// Update user profile
app.put('/api/user', requireAuth, handleAsync(async (req, res) => {
  const { fullName, preferences } = req.body;
  const updateData = {};
  
  if (fullName) updateData.fullName = fullName.trim();
  if (preferences) updateData.preferences = preferences;
  
  const user = await userDB.updateUser(req.userId, updateData);
  res.json({
    success: true,
    message: 'Profile updated successfully',
    user
  });
}));

// Change password
app.put('/api/user/password', requireAuth, handleAsync(async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ 
      success: false,
      error: 'Missing password fields',
      message: 'Current password and new password are required'
    });
  }
  
  if (newPassword.length < 6) {
    return res.status(400).json({ 
      success: false,
      error: 'Password too short',
      message: 'New password must be at least 6 characters long'
    });
  }
  
  const result = await userDB.changePassword(req.userId, currentPassword, newPassword);
  res.json({
    success: true,
    ...result
  });
}));

// Get user statistics
app.get('/api/user/stats', requireAuth, handleAsync(async (req, res) => {
  const stats = await userDB.getUserStats(req.userId);
  res.json({
    success: true,
    stats
  });
}));

// Delete user account
app.delete('/api/user', requireAuth, handleAsync(async (req, res) => {
  const { password } = req.body;
  
  if (!password) {
    return res.status(400).json({ 
      success: false,
      error: 'Password required',
      message: 'Please provide your password to delete your account'
    });
  }
  
  // Verify password before deletion
  const user = await userDB.getUserById(req.userId);
  await userDB.authenticateUser(user.email, password);
  
  // Delete user account
  const result = await userDB.deleteUser(req.userId);
  
  // Clear auth cookie
  res.clearCookie('authToken');
  res.json({
    success: true,
    ...result
  });
}));

// ============================================================================
// ITINERARY ROUTES
// ============================================================================

// Generate new itinerary (AI-powered)
app.post('/api/generate-itinerary', requireAuth, handleAsync(async (req, res) => {
  const userPreferences = req.body;
  
  console.log('🚀 Starting itinerary generation for user:', req.username);
  console.log('Preferences:', userPreferences);
  
  const itinerary = await generateItinerary(userPreferences);
  
  res.json({
    success: true,
    message: 'Itinerary generated successfully',
    ...itinerary
  });
}));

// Save itinerary to database
app.post('/api/save-itinerary', requireAuth, handleAsync(async (req, res) => {
  const { itinerary: itineraryData, title, notes } = req.body;
  
  // Prepare itinerary data for database
  const itineraryToSave = {
    title: title || `Trip to ${itineraryData.destination}`,
    destination: itineraryData.destination,
    startDate: new Date(),
    endDate: new Date(),
    duration: itineraryData.duration,
    totalBudget: 0,
    estimatedCost: itineraryData.totalEstimatedCost,
    travelers: 1,
    interests: [],
    accommodationType: 'Mid-range',
    transportationType: 'Public Transport',
    itinerary: itineraryData,
    additionalTips: itineraryData.additionalTips || [],
    notes: notes || ''
  };
  
  const savedItinerary = await itineraryDB.saveItinerary(req.userId, itineraryToSave);
  
  res.status(201).json({
    success: true,
    message: 'Trip saved successfully to your collection!',
    itinerary: savedItinerary
  });
}));

// Get all saved itineraries for user
app.get('/api/saved-itineraries', requireAuth, handleAsync(async (req, res) => {
  const { page, limit, sortBy, sortOrder, status, search, destination } = req.query;
  
  const options = {
    page: parseInt(page) || 1,
    limit: parseInt(limit) || 10,
    sortBy: sortBy || 'createdAt',
    sortOrder: sortOrder || 'desc',
    status: status || null,
    destination: destination || null
  };
  
  let result;
  
  try {
    if (search) {
      result = await itineraryDB.searchItineraries(req.userId, search, options);
    } else {
      result = await itineraryDB.getUserItineraries(req.userId, options);
    }
    
    console.log('Sending saved itineraries:', {
      count: result.itineraries?.length || 0,
      total: result.pagination?.total || 0
    });
    
    res.json({
      success: true,
      ...result
    });
  } catch (error) {
    console.error('Error fetching saved itineraries:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch saved itineraries',
      message: error.message
    });
  }
}));

// Get specific itinerary
app.get('/api/saved-itineraries/:id', requireAuth, handleAsync(async (req, res) => {
  const itinerary = await itineraryDB.getItineraryById(req.params.id, req.userId);
  res.json({
    success: true,
    itinerary
  });
}));

// Update itinerary
app.put('/api/saved-itineraries/:id', requireAuth, handleAsync(async (req, res) => {
  const { title, notes, rating, status, isPublic, tags } = req.body;
  
  const updateData = {};
  if (title !== undefined) updateData.title = title.trim();
  if (notes !== undefined) updateData.notes = notes;
  if (rating !== undefined) updateData.rating = parseInt(rating);
  if (status !== undefined) updateData.status = status;
  if (isPublic !== undefined) updateData.isPublic = isPublic;
  if (tags !== undefined) updateData.tags = tags;
  
  const itinerary = await itineraryDB.updateItinerary(
    req.params.id,
    req.userId,
    updateData
  );
  
  res.json({
    success: true,
    message: 'Trip updated successfully',
    itinerary
  });
}));

// Delete itinerary
app.delete('/api/saved-itineraries/:id', requireAuth, handleAsync(async (req, res) => {
  const result = await itineraryDB.deleteItinerary(req.params.id, req.userId);
  res.json({
    success: true,
    ...result
  });
}));

// Get itinerary statistics
app.get('/api/itineraries/stats', requireAuth, handleAsync(async (req, res) => {
  const stats = await itineraryDB.getItineraryStats(req.userId);
  res.json({
    success: true,
    stats
  });
}));

// ============================================================================
// PDF GENERATION ROUTE
// ============================================================================

app.post('/api/generate-pdf', requireAuth, handleAsync(async (req, res) => {
  const { itinerary } = req.body;
  
  if (!itinerary) {
    return res.status(400).json({ 
      success: false,
      error: 'Missing itinerary data',
      message: 'Itinerary data is required to generate PDF'
    });
  }
  
  try {
    // Create a new PDF document
    const doc = new PDFDocument({ 
      margin: 50,
      size: 'A4',
      info: {
        Title: `Travel Itinerary - ${itinerary.destination}`,
        Author: 'AI Travel Planner',
        Subject: 'Travel Itinerary',
        Keywords: 'travel, itinerary, trip, vacation, ai'
      }
    });
    
    // Set response headers
    const filename = `Travel-Itinerary-${itinerary.destination.replace(/[^a-zA-Z0-9]/g, '-')}-${Date.now()}.pdf`;
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Cache-Control', 'no-cache');
    
    // Pipe the PDF to the response
    doc.pipe(res);
    
    // Add header
    doc.fontSize(24).font('Helvetica-Bold').fillColor('#2563eb')
       .text('✈️ AI Travel Planner', { align: 'center' });
    doc.moveDown(0.5);
    
    doc.fontSize(18).font('Helvetica-Bold').fillColor('#1f2937')
       .text(`Travel Itinerary: ${itinerary.destination}`, { align: 'center' });
    doc.moveDown(1);
    
    // Add overview
    doc.fontSize(12).fillColor('#374151')
       .text(`Duration: ${itinerary.duration}`)
       .text(`Total Budget: ${itinerary.totalEstimatedCost}`)
       .text(`Generated: ${new Date().toLocaleDateString()}`)
       .moveDown(1);
    
    // Add each day
    if (itinerary.itinerary && Array.isArray(itinerary.itinerary)) {
      itinerary.itinerary.forEach((day, index) => {
        // Check if we need a new page
        if (doc.y > 650) {
          doc.addPage();
        }
        
        // Day header
        doc.fontSize(16).font('Helvetica-Bold').fillColor('#3b82f6')
           .text(`Day ${day.day} - ${new Date(day.date).toLocaleDateString()}`)
           .moveDown(0.5);
        
        // Activities
        if (day.activities && Array.isArray(day.activities)) {
          doc.fontSize(14).font('Helvetica-Bold').fillColor('#059669')
             .text('Activities:');
          
          day.activities.forEach((activity) => {
            if (doc.y > 700) {
              doc.addPage();
            }
            
            doc.fontSize(12).font('Helvetica-Bold').fillColor('#1f2937')
               .text(`• ${activity.activity || 'Activity'} (${activity.time || 'All Day'})`, { indent: 20 });
            doc.fontSize(10).font('Helvetica').fillColor('#6b7280')
               .text(`  Location: ${activity.location || 'TBD'}`, { indent: 20 })
               .text(`  Cost: ${activity.estimatedCost || 'TBD'}`, { indent: 20 })
               .text(`  ${activity.description || ''}`, { indent: 20 });
            doc.moveDown(0.3);
          });
        }
        
        // Meals
        if (day.meals && Array.isArray(day.meals)) {
          doc.fontSize(14).font('Helvetica-Bold').fillColor('#ea580c')
             .text('Meals:');
          
          day.meals.forEach((meal) => {
            doc.fontSize(12).font('Helvetica')
               .text(`• ${meal.type || 'Meal'}: ${meal.recommendation || 'TBD'} (${meal.estimatedCost || 'TBD'})`, { indent: 20 });
          });
        }
        
        doc.moveDown(1);
      });
    }
    
    // Add tips
    if (itinerary.additionalTips && Array.isArray(itinerary.additionalTips)) {
      doc.addPage();
      doc.fontSize(16).font('Helvetica-Bold').fillColor('#f59e0b')
         .text('Local Tips:')
         .moveDown(0.5);
      
      itinerary.additionalTips.forEach((tip, index) => {
        doc.fontSize(12).font('Helvetica')
           .text(`${index + 1}. ${tip}`)
           .moveDown(0.3);
      });
    }
    
    // Add footer
    doc.fontSize(8).fillColor('#9ca3af')
       .text(`Generated by AI Travel Planner - ${new Date().toLocaleString()}`, 
             50, doc.page.height - 30, { align: 'center' });
    
    // Finalize the PDF
    doc.end();
    
    console.log(`✅ PDF generated successfully for user ${req.username}`);
    
  } catch (error) {
    console.error('💥 PDF generation error:', error);
    
    if (!res.headersSent) {
      res.status(500).json({ 
        success: false,
        error: 'PDF generation failed',
        message: 'Could not generate PDF at this time. Please try again.'
      });
    }
  }
}));

// ============================================================================
// AI GENERATION FUNCTIONS
// ============================================================================

// Helper function to clean and parse JSON from AI response
function parseAIResponse(text) {
  try {
    // First, try to extract JSON from code blocks
    const codeBlockMatch = text.match(/```json\n([\s\S]*?)\n```/);
    if (codeBlockMatch) {
      return JSON.parse(codeBlockMatch[1]);
    }
    
    // If no code block, look for JSON object
    const jsonMatch = text.match(/{[\s\S]*}/);
    if (jsonMatch) {
      let jsonStr = jsonMatch[0];
      
      // Clean up common JSON issues
      jsonStr = cleanJsonString(jsonStr);
      
      return JSON.parse(jsonStr);
    }
    
    throw new Error("No valid JSON found in response");
  } catch (error) {
    console.error('JSON parsing failed:', error.message);
    throw new Error(`Failed to parse AI response: ${error.message}`);
  }
}

// Helper function to clean JSON strings
function cleanJsonString(jsonStr) {
  // Remove any text before the first {
  jsonStr = jsonStr.substring(jsonStr.indexOf('{'));
  
  // Remove any text after the last }
  const lastBrace = jsonStr.lastIndexOf('}');
  if (lastBrace !== -1) {
    jsonStr = jsonStr.substring(0, lastBrace + 1);
  }
  
  // Fix common JSON issues
  jsonStr = jsonStr
    .replace(/,(\s*[}\]])/g, '$1')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/\/\/.*$/gm, '')
    .replace(/,+/g, ',')
    .replace(/}(\s*){/g, '},\n$1{')
    .replace(/](\s*)\[/g, '],\n$1[');
  
  return jsonStr;
}

// Function to generate travel itinerary using AI
async function generateItinerary(userPreferences) {
  console.log('🚀 Starting itinerary generation with preferences:', userPreferences);
  
  try {
    // Check if AI is available
    if (!genAI) {
      console.log('⚠️ AI not available, using fallback');
      return createFallbackItinerary(userPreferences);
    }
    
    const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });
    
    const prompt = `
Create a detailed travel itinerary. Return ONLY valid JSON without any additional text.

User Preferences:
- Destination: ${userPreferences.destination}
- Start Date: ${userPreferences.startDate}
- End Date: ${userPreferences.endDate}
- Budget: ${userPreferences.budget} INR
- Travelers: ${userPreferences.travelers || 1}
- Interests: ${userPreferences.interests.join(', ')}
- Accommodation: ${userPreferences.accommodationType}
- Transportation: ${userPreferences.transportationType}

Return this JSON structure:

{
  "destination": "${userPreferences.destination}",
  "duration": "X days",
  "totalEstimatedCost": "XXXX INR",
  "itinerary": [
    {
      "day": 1,
      "date": "${userPreferences.startDate}",
      "activities": [
        {
          "time": "Morning",
          "activity": "Activity name",
          "description": "Brief description",
          "estimatedCost": "500 INR",
          "location": "Location name",
          "travelTime": "30 minutes"
        }
      ],
      "meals": [
        {
          "type": "Breakfast",
          "recommendation": "Restaurant name",
          "cuisine": "Local cuisine",
          "estimatedCost": "300 INR",
          "location": "Location"
        }
      ],
      "accommodation": {
        "name": "Hotel name",
        "type": "${userPreferences.accommodationType}",
        "estimatedCost": "2000 INR",
        "location": "Location"
      }
    }
  ],
  "additionalTips": [
    "Local tip 1",
    "Local tip 2"
  ]
}

Requirements:
- Stay within budget of ${userPreferences.budget} INR
- Include 2-3 activities per day
- All costs in INR
- Focus on: ${userPreferences.interests.join(', ')}
- Return ONLY the JSON object
`;

    console.log('📝 Sending request to Gemini API...');
    
    const result = await model.generateContent(prompt);
    const response = await result.response;
    const text = response.text();
    
    console.log('✅ Received response from Gemini API');
    console.log('Response length:', text.length);
    
    // Parse the JSON response
    let itinerary;
    try {
      itinerary = parseAIResponse(text);
      console.log('✅ Successfully parsed AI response');
    } catch (parseError) {
      console.error('❌ Failed to parse AI response:', parseError.message);
      console.log('🔄 Creating fallback itinerary...');
      itinerary = createFallbackItinerary(userPreferences);
    }
    
    // Validate the itinerary structure
    if (!validateItineraryStructure(itinerary)) {
      console.error('❌ Invalid itinerary structure, using fallback');
      itinerary = createFallbackItinerary(userPreferences);
    }
    
    console.log('✅ Itinerary generated successfully');
    return itinerary;
    
  } catch (error) {
    console.error("💥 Error generating itinerary:", error);
    console.log('🔄 Creating fallback itinerary due to error...');
    return createFallbackItinerary(userPreferences);
  }
}

// Function to validate itinerary structure
function validateItineraryStructure(itinerary) {
  if (!itinerary || typeof itinerary !== 'object') return false;
  if (!itinerary.destination || !itinerary.duration || !itinerary.totalEstimatedCost) return false;
  if (!Array.isArray(itinerary.itinerary) || itinerary.itinerary.length === 0) return false;
  
  const firstDay = itinerary.itinerary[0];
  if (!firstDay.day || !firstDay.date || !Array.isArray(firstDay.activities)) return false;
  
  return true;
}

// Function to create a fallback itinerary when AI fails
function createFallbackItinerary(userPreferences) {
  console.log('🔄 Creating fallback itinerary for:', userPreferences.destination);
  
  const startDate = new Date(userPreferences.startDate);
  const endDate = new Date(userPreferences.endDate);
  const dayCount = Math.ceil((endDate - startDate) / (1000 * 60 * 60 * 24)) + 1;
  
  const budgetPerDay = Math.floor(userPreferences.budget / dayCount);
  const accommodationCost = budgetPerDay * 0.4;
  const foodCost = budgetPerDay * 0.3;
  const activityCost = budgetPerDay * 0.3;
  
  const fallbackItinerary = {
    destination: userPreferences.destination,
    duration: `${dayCount} ${dayCount === 1 ? 'day' : 'days'}`,
    totalEstimatedCost: `${userPreferences.budget} INR`,
    itinerary: [],
    additionalTips: [
      `Best time to visit ${userPreferences.destination} varies by season - check weather conditions`,
      "Carry a valid ID and emergency contacts at all times",
      "Keep digital and physical copies of important documents",
      "Research local customs and cultural etiquette before your trip",
      "Keep emergency cash in local currency",
      "Download offline maps and translation apps",
      "Check visa requirements and travel advisories",
      "Pack according to local weather and cultural dress codes"
    ]
  };
  
  // Create daily itinerary
  for (let i = 0; i < dayCount; i++) {
    const currentDate = new Date(startDate);
    currentDate.setDate(startDate.getDate() + i);
    
    const day = {
      day: i + 1,
      date: currentDate.toISOString().split('T')[0],
     activities: [],
     meals: [],
     accommodation: null
   };
   
   // Add activities based on interests
   const interests = userPreferences.interests || ['Sightseeing'];
   interests.forEach((interest, index) => {
     const timeSlots = ['Morning', 'Afternoon', 'Evening'];
     const timeSlot = timeSlots[index % 3];
     
     day.activities.push({
       time: timeSlot,
       activity: `${interest} Experience in ${userPreferences.destination}`,
       description: `Explore ${interest.toLowerCase()} attractions and activities in ${userPreferences.destination}`,
       estimatedCost: `${Math.floor(activityCost / 3)} INR`,
       location: `${userPreferences.destination} City Center`,
       travelTime: "20-30 minutes"
     });
   });
   
   // Ensure at least 2 activities per day
   while (day.activities.length < 2) {
     day.activities.push({
       time: day.activities.length === 0 ? 'Morning' : 'Afternoon',
       activity: `Explore ${userPreferences.destination}`,
       description: `Discover the main attractions and local culture of ${userPreferences.destination}`,
       estimatedCost: `${Math.floor(activityCost / 3)} INR`,
       location: userPreferences.destination,
       travelTime: "15-25 minutes"
     });
   }
   
   // Add meals
   day.meals = [
     {
       type: "Breakfast",
       recommendation: `Local Breakfast Spot`,
       cuisine: "Local Cuisine",
       estimatedCost: `${Math.floor(foodCost * 0.25)} INR`,
       location: `Near your accommodation`
     },
     {
       type: "Lunch",
       recommendation: `Popular Local Restaurant`,
       cuisine: "Regional Specialties",
       estimatedCost: `${Math.floor(foodCost * 0.35)} INR`,
       location: `${userPreferences.destination} Downtown`
     },
     {
       type: "Dinner",
       recommendation: `Traditional Restaurant`,
       cuisine: "Local Delicacies",
       estimatedCost: `${Math.floor(foodCost * 0.4)} INR`,
       location: `${userPreferences.destination} Main Area`
     }
   ];
   
   // Add accommodation (except for last day)
   if (i < dayCount - 1) {
     day.accommodation = {
       name: `${userPreferences.accommodationType} Hotel ${userPreferences.destination}`,
       type: userPreferences.accommodationType,
       estimatedCost: `${Math.floor(accommodationCost)} INR`,
       location: `Central ${userPreferences.destination}`
     };
   }
   
   fallbackItinerary.itinerary.push(day);
 }
 
 console.log('✅ Fallback itinerary created successfully');
 return fallbackItinerary;
}

// ============================================================================
// ADDITIONAL API ROUTES (Flights, Accommodations, Activities)
// ============================================================================

// Get flight recommendations
app.post('/api/flights', requireAuth, handleAsync(async (req, res) => {
 const { origin, destination, date } = req.body;
 
 if (!origin || !destination || !date) {
   return res.status(400).json({ 
     success: false,
     error: 'Missing required fields',
     message: 'Origin, destination, and date are required'
   });
 }
 
 try {
   const flights = await getFlightRecommendations(origin, destination, date);
   res.json(flights);
 } catch (error) {
   console.error('Error getting flight recommendations:', error);
   res.status(500).json({
     success: false,
     error: 'Failed to get flight recommendations',
     message: error.message
   });
 }
}));

// Get accommodation recommendations
app.post('/api/accommodations', requireAuth, handleAsync(async (req, res) => {
 const { destination, checkIn, checkOut, preferences } = req.body;
 
 if (!destination || !checkIn || !checkOut) {
   return res.status(400).json({ 
     success: false,
     error: 'Missing required fields',
     message: 'Destination, check-in date, and check-out date are required'
   });
 }
 
 try {
   const accommodations = await getAccommodationRecommendations(
     destination, 
     checkIn, 
     checkOut, 
     preferences || 'Mid-range'
   );
   
   res.json(accommodations);
 } catch (error) {
   console.error('Error getting accommodation recommendations:', error);
   res.status(500).json({
     success: false,
     error: 'Failed to get accommodation recommendations',
     message: error.message
   });
 }
}));

// Get activity recommendations
app.post('/api/activities', requireAuth, handleAsync(async (req, res) => {
 const { destination, interests } = req.body;
 
 if (!destination || !interests || interests.length === 0) {
   return res.status(400).json({ 
     success: false,
     error: 'Missing required fields',
     message: 'Destination and at least one interest are required'
   });
 }
 
 try {
   const activities = await getActivityRecommendations(destination, interests);
   res.json(activities);
 } catch (error) {
   console.error('Error getting activity recommendations:', error);
   res.status(500).json({
     success: false,
     error: 'Failed to get activity recommendations',
     message: error.message
   });
 }
}));

// Flight recommendations function
async function getFlightRecommendations(origin, destination, date) {
 try {
   if (!genAI) {
     return createFallbackFlights(origin, destination);
   }
   
   const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });
   
   const prompt = `
Provide flight recommendations from ${origin} to ${destination} on ${date}.
Return ONLY valid JSON array without any additional text.

JSON format:
[
 {
   "airline": "Airline name",
   "flightNumber": "XX123",
   "departureTime": "HH:MM",
   "arrivalTime": "HH:MM",
   "duration": "Xh Ym",
   "price": "XXXX INR",
   "stops": 0,
   "departureAirport": "Origin Airport Code",
   "arrivalAirport": "Destination Airport Code"
 }
]

Provide 3-5 realistic flight options with varying prices. All prices in INR.
`;

   const result = await model.generateContent(prompt);
   const response = await result.response;
   const text = response.text();
   
   try {
     let flights = parseAIResponse(text);
     if (!Array.isArray(flights)) {
       flights = [flights];
     }
     return flights;
   } catch (error) {
     console.error('Flight parsing failed, using fallback');
     return createFallbackFlights(origin, destination);
   }
   
 } catch (error) {
   console.error("Error getting flight recommendations:", error);
   return createFallbackFlights(origin, destination);
 }
}

// Fallback flight data
function createFallbackFlights(origin, destination) {
 return [
   {
     airline: "Air India",
     flightNumber: "AI101",
     departureTime: "08:00",
     arrivalTime: "10:30",
     duration: "2h 30m",
     price: "8500 INR",
     stops: 0,
     departureAirport: origin,
     arrivalAirport: destination
   },
   {
     airline: "IndiGo",
     flightNumber: "6E234",
     departureTime: "14:15",
     arrivalTime: "16:45",
     duration: "2h 30m",
     price: "7200 INR",
     stops: 0,
     departureAirport: origin,
     arrivalAirport: destination
   },
   {
     airline: "SpiceJet",
     flightNumber: "SG567",
     departureTime: "19:20",
     arrivalTime: "21:50",
     duration: "2h 30m",
     price: "6800 INR",
     stops: 0,
     departureAirport: origin,
     arrivalAirport: destination
   }
 ];
}

// Accommodation recommendations function
async function getAccommodationRecommendations(destination, checkIn, checkOut, preferences) {
 try {
   if (!genAI) {
     return createFallbackAccommodations(destination, preferences);
   }
   
   const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });
   
   const prompt = `
Provide accommodation recommendations in ${destination} for ${checkIn} to ${checkOut}.
Preference: ${preferences}
Return ONLY valid JSON array without any additional text.

JSON format:
[
 {
   "name": "Hotel name",
   "type": "Hotel/Hostel/Apartment",
   "pricePerNight": "XXXX INR",
   "totalPrice": "XXXX INR", 
   "location": "Area in ${destination}",
   "rating": "4.5",
   "amenities": ["WiFi", "Pool", "Gym"],
   "description": "Brief description"
 }
]

Provide 5 realistic ${preferences} accommodations. All prices in INR.
`;

   const result = await model.generateContent(prompt);
   const response = await result.response;
   const text = response.text();
   
   try {
     let accommodations = parseAIResponse(text);
     if (!Array.isArray(accommodations)) {
       accommodations = [accommodations];
     }
     return accommodations;
   } catch (error) {
     console.error('Accommodation parsing failed, using fallback');
     return createFallbackAccommodations(destination, preferences);
   }
   
 } catch (error) {
   console.error("Error getting accommodation recommendations:", error);
   return createFallbackAccommodations(destination, preferences);
 }
}

// Fallback accommodation data
function createFallbackAccommodations(destination, preferences) {
 const basePrice = preferences === 'Budget' ? 1500 : preferences === 'Luxury' ? 8000 : 3500;
 
 return [
   {
     name: `${preferences} Hotel ${destination}`,
     type: "Hotel",
     pricePerNight: `${basePrice} INR`,
     totalPrice: `${basePrice * 3} INR`,
     location: `Central ${destination}`,
     rating: "4.2",
     amenities: ["WiFi", "Room Service", "AC"],
     description: `Comfortable ${preferences.toLowerCase()} accommodation in ${destination}`
   },
   {
     name: `${destination} Resort`,
     type: "Resort",
     pricePerNight: `${basePrice + 500} INR`,
     totalPrice: `${(basePrice + 500) * 3} INR`,
     location: `${destination} Downtown`,
     rating: "4.0",
     amenities: ["Pool", "Restaurant", "WiFi"],
     description: `Popular resort option in ${destination}`
   },
   {
     name: `Grand ${destination} Palace`,
     type: "Hotel",
     pricePerNight: `${basePrice + 1000} INR`,
     totalPrice: `${(basePrice + 1000) * 3} INR`,
     location: `${destination} Business District`,
     rating: "4.5",
     amenities: ["WiFi", "Gym", "Spa", "Restaurant"],
     description: `Luxury hotel in the heart of ${destination}`
   }
 ];
}

// Activity recommendations function
async function getActivityRecommendations(destination, interests) {
 try {
   if (!genAI) {
     return createFallbackActivities(destination, interests);
   }
   
   const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });
   
   const prompt = `
Provide activity recommendations in ${destination} for interests: ${interests.join(', ')}.
Return ONLY valid JSON array without any additional text.

JSON format:
[
 {
   "name": "Activity name",
   "category": "Category",
   "description": "Description",
   "estimatedCost": "XXX INR",
   "duration": "X hours",
   "location": "Location in ${destination}",
   "bestTimeToVisit": "Morning/Afternoon/Evening"
 }
]

Provide 8-10 activities matching the interests. All costs in INR.
`;

   const result = await model.generateContent(prompt);
   const response = await result.response;
   const text = response.text();
   
   try {
     let activities = parseAIResponse(text);
     if (!Array.isArray(activities)) {
       activities = [activities];
     }
     return activities;
   } catch (error) {
     console.error('Activity parsing failed, using fallback');
     return createFallbackActivities(destination, interests);
   }
   
 } catch (error) {
   console.error("Error getting activity recommendations:", error);
   return createFallbackActivities(destination, interests);
 }
}

// Fallback activity data
function createFallbackActivities(destination, interests) {
 const activities = [];
 
 interests.forEach(interest => {
   switch (interest.toLowerCase()) {
     case 'history':
       activities.push({
         name: `${destination} Historical Tour`,
         category: "History",
         description: "Explore historical landmarks and museums",
         estimatedCost: "500 INR",
         duration: "3 hours",
         location: destination,
         bestTimeToVisit: "Morning"
       });
       break;
     case 'nature':
       activities.push({
         name: "Nature Walk",
         category: "Nature",
         description: "Scenic nature walks and park visits",
         estimatedCost: "200 INR",
         duration: "2 hours",
         location: destination,
         bestTimeToVisit: "Evening"
       });
       break;
     case 'food':
       activities.push({
         name: "Food Tour",
         category: "Food",
         description: "Local cuisine tasting tour",
         estimatedCost: "800 INR",
         duration: "4 hours",
         location: destination,
         bestTimeToVisit: "Afternoon"
       });
       break;
     case 'art':
       activities.push({
         name: "Art Gallery Visit",
         category: "Art",
         description: "Visit local art galleries and exhibitions",
         estimatedCost: "400 INR",
         duration: "2 hours",
         location: destination,
         bestTimeToVisit: "Afternoon"
       });
       break;
     case 'adventure':
       activities.push({
         name: "Adventure Sports",
         category: "Adventure",
         description: "Thrilling adventure activities and sports",
         estimatedCost: "1200 INR",
         duration: "4 hours",
         location: destination,
         bestTimeToVisit: "Morning"
       });
       break;
     case 'shopping':
       activities.push({
         name: "Shopping Tour",
         category: "Shopping",
         description: "Visit local markets and shopping centers",
         estimatedCost: "600 INR",
         duration: "3 hours",
         location: destination,
         bestTimeToVisit: "Afternoon"
       });
       break;
     case 'nightlife':
       activities.push({
         name: "Nightlife Experience",
         category: "Nightlife",
         description: "Experience local bars and entertainment",
         estimatedCost: "1000 INR",
         duration: "4 hours",
         location: destination,
         bestTimeToVisit: "Evening"
       });
       break;
     case 'relaxation':
       activities.push({
         name: "Spa & Wellness",
         category: "Relaxation",
         description: "Relax and rejuvenate at local spas",
         estimatedCost: "800 INR",
         duration: "3 hours",
         location: destination,
         bestTimeToVisit: "Afternoon"
       });
       break;
     default:
       activities.push({
         name: `${interest} Experience`,
         category: interest,
         description: `Enjoy ${interest.toLowerCase()} activities in ${destination}`,
         estimatedCost: "600 INR",
         duration: "3 hours",
         location: destination,
         bestTimeToVisit: "Afternoon"
       });
   }
 });
 
 // Add some general activities if we have less than 5
 while (activities.length < 5) {
   activities.push({
     name: `Explore ${destination}`,
     category: "Sightseeing",
     description: `General sightseeing and exploration of ${destination}`,
     estimatedCost: "500 INR",
     duration: "3 hours",
     location: destination,
     bestTimeToVisit: "Morning"
   });
 }
 
 return activities.slice(0, 8); // Limit to 8 activities
}

// ============================================================================
// DEBUG AND UTILITY ROUTES
// ============================================================================

// Test route for itinerary generation
app.post('/api/test-generate', requireAuth, handleAsync(async (req, res) => {
 console.log('🧪 Test route called');
 
 const testPreferences = {
   destination: 'Goa, India',
   startDate: '2024-01-15',
   endDate: '2024-01-17',
   budget: 15000,
   travelers: 2,
   interests: ['Beach', 'Food'],
   accommodationType: 'Mid-range',
   transportationType: 'Rental Car'
 };
 
 try {
   const result = createFallbackItinerary(testPreferences);
   res.json({
     success: true,
     message: 'Test itinerary generated',
     ...result
   });
 } catch (error) {
   res.status(500).json({
     success: false,
     error: error.message
   });
 }
}));

// Debug route to check environment
app.get('/api/debug/env', requireAuth, handleAsync(async (req, res) => {
 res.json({
   success: true,
   environment: {
     nodeEnv: process.env.NODE_ENV,
     hasGeminiKey: !!process.env.GEMINI_API_KEY,
     hasMongoUri: !!process.env.MONGODB_URI,
     hasJwtSecret: !!JWT_SECRET,
     geminiKeyLength: process.env.GEMINI_API_KEY ? process.env.GEMINI_API_KEY.length : 0,
     aiAvailable: !!genAI,
     authType: 'JWT'
   }
 });
}));

// Debug route to check JWT token
app.get('/api/debug/token', requireAuth, handleAsync(async (req, res) => {
 const token = req.cookies.authToken;
 const decoded = verifyToken(token);
 
 res.json({
   success: true,
   tokenExists: !!token,
   tokenValid: !!decoded,
   userId: req.userId,
   username: req.username,
   email: req.userEmail,
   tokenData: decoded
 });
}));

// Health check endpoint
app.get('/api/health', (req, res) => {
 res.json({
   success: true,
   message: 'AI Travel Planner API is running',
   timestamp: new Date().toISOString(),
   database: database.getConnectionStatus(),
   version: '4.0.0',
   authType: 'JWT',
   features: {
     aiGeneration: !!genAI,
     pdfGeneration: true,
     userAuthentication: true,
     cloudStorage: database.isConnected(),
     jwtAuth: true
   }
 });
});

// Database status endpoint
app.get('/api/database/status', requireAuth, handleAsync(async (req, res) => {
 const status = {
   connected: database.isConnected(),
   connectionString: 'MongoDB Atlas',
   status: database.getConnectionStatus(),
   timestamp: new Date().toISOString()
 };
 
 if (database.isConnected()) {
   try {
     const userCount = await userDB.User.countDocuments();
     const itineraryCount = await itineraryDB.Itinerary.countDocuments();
     
     status.stats = {
       totalUsers: userCount,
       totalItineraries: itineraryCount,
       lastChecked: new Date().toISOString()
     };
   } catch (error) {
     status.error = error.message;
   }
 }
 
 res.json({
   success: true,
   database: status
 });
}));

// ============================================================================
// STATIC FILE SERVING
// ============================================================================

// Serve the main page
app.get('/', (req, res) => {
 res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Serve favicon
app.get('/favicon.ico', (req, res) => {
 res.status(204).send();
});

// ============================================================================
// ERROR HANDLING MIDDLEWARE
// ============================================================================

// 404 handler for API routes
app.use('/api/*', (req, res) => {
 res.status(404).json({
   success: false,
   error: 'API endpoint not found',
   message: `The endpoint ${req.method} ${req.path} does not exist`,
   availableEndpoints: [
     'POST /api/register',
     'POST /api/login',
     'POST /api/logout',
     'GET /api/user',
     'PUT /api/user',
     'PUT /api/user/password',
     'GET /api/user/stats',
     'DELETE /api/user',
     'POST /api/generate-itinerary',
     'POST /api/save-itinerary',
     'GET /api/saved-itineraries',
     'GET /api/saved-itineraries/:id',
     'PUT /api/saved-itineraries/:id',
     'DELETE /api/saved-itineraries/:id',
     'GET /api/itineraries/stats',
     'POST /api/generate-pdf',
     'POST /api/flights',
     'POST /api/accommodations',
     'POST /api/activities',
     'POST /api/test-generate',
     'GET /api/debug/env',
     'GET /api/debug/token',
     'GET /api/health',
     'GET /api/database/status'
   ]
 });
});

// Global error handler
app.use((err, req, res, next) => {
 console.error('💥 Unhandled error:', err);
 
 // Handle specific error types
 if (err.name === 'ValidationError') {
   return res.status(400).json({
     success: false,
     error: 'Validation Error',
     message: err.message,
     details: Object.values(err.errors || {}).map(e => e.message)
   });
 }
 
 if (err.name === 'CastError') {
   return res.status(400).json({
     success: false,
     error: 'Invalid ID format',
     message: 'The provided ID is not valid'
   });
 }
 
 if (err.code === 11000) {
   return res.status(400).json({
     success: false,
     error: 'Duplicate Error',
     message: 'A record with this information already exists'
   });
 }
 
 if (err.message && err.message.includes('Invalid credentials')) {
   return res.status(401).json({
     success: false,
     error: 'Authentication Error',
     message: err.message
   });
 }
 
 if (err.message && (err.message.includes('not found') || err.message.includes('access denied'))) {
   return res.status(404).json({
     success: false,
     error: 'Not Found',
     message: err.message
   });
 }
 
 // Default error response
 res.status(err.status || 500).json({
   success: false,
   error: 'Internal Server Error',
   message: process.env.NODE_ENV === 'production' 
     ? 'Something went wrong on our end. Please try again later.'
     : err.message,
   ...(process.env.NODE_ENV !== 'production' && { stack: err.stack })
 });
});

// ============================================================================
// GRACEFUL SHUTDOWN HANDLING
// ============================================================================

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
 console.error('💥 Uncaught Exception:', error);
 
 // Don't exit immediately for PDF generation errors
 if (error.message && error.message.includes('write after end')) {
   console.log('⚠️ PDF generation stream error - continuing...');
   return;
 }
 
 process.exit(1);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
 console.error('💥 Unhandled Rejection at:', promise, 'reason:', reason);
 
 // Don't exit for PDF stream errors
 if (reason && reason.message && reason.message.includes('write after end')) {
   console.log('⚠️ PDF generation promise rejection - continuing...');
   return;
 }
 
 if (process.env.NODE_ENV !== 'production') {
   process.exit(1);
 }
});

// Graceful shutdown
process.on('SIGINT', async () => {
 console.log('\n🛑 Received SIGINT. Graceful shutdown initiated...');
 
 try {
   await database.disconnect();
   console.log('✅ Database disconnected');
   
   process.exit(0);
 } catch (error) {
   console.error('❌ Error during shutdown:', error);
   process.exit(1);
 }
});

process.on('SIGTERM', async () => {
 console.log('\n🛑 Received SIGTERM. Graceful shutdown initiated...');
 
 try {
   await database.disconnect();
   console.log('✅ Database disconnected');
   
   process.exit(0);
 } catch (error) {
   console.error('❌ Error during shutdown:', error);
   process.exit(1);
 }
});

// ============================================================================
// START SERVER
// ============================================================================

// Start the server
const server = app.listen(PORT, () => {
 console.log(`
🚀 AI Travel Planner Server Started Successfully!

📊 Server Details:
 • Port: ${PORT}
 • Environment: ${process.env.NODE_ENV || 'development'}
 • Database: ${database.getConnectionStatus()}
 • AI Service: ${genAI ? 'Available' : 'Fallback Mode'}
 • Authentication: JWT-based
 • URL: http://localhost:${PORT}

🗄️ Database Information:
 • Connection: MongoDB Atlas (Cloud)
 • Storage: Persistent
 • Collections: Users, Itineraries

🔐 Authentication:
 • Type: JSON Web Tokens (JWT)
 • Storage: HTTP-only cookies
 • Expiry: 24 hours

🎯 Available Services:
 • AI Itinerary Generation ${genAI ? '✅' : '⚠️ (Fallback)'}
 • User Authentication ✅
 • Trip Management ✅
 • PDF Export ✅
 • Flight/Hotel/Activity Recommendations ${genAI ? '✅' : '⚠️ (Fallback)'}
 • Cloud Data Storage ✅

📚 API Endpoints:
 • Health Check: http://localhost:${PORT}/api/health
 • Database Status: http://localhost:${PORT}/api/database/status
 • Environment Debug: http://localhost:${PORT}/api/debug/env
 • Token Debug: http://localhost:${PORT}/api/debug/token

Ready to plan amazing trips with JWT authentication! ✈️🌍🔐
 `);
});

// Handle server errors
server.on('error', (error) => {
 if (error.code === 'EADDRINUSE') {
   console.error(`❌ Port ${PORT} is already in use. Please try a different port.`);
 } else {
   console.error('❌ Server error:', error);
 }
 process.exit(1);
});

// Export app for testing
module.exports = app;