const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

// Database connection state
let isConnected = false;

// User Schema
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3,
    maxlength: 30
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  },
  fullName: {
    type: String,
    required: true,
    trim: true
  },
  preferences: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  lastLogin: {
    type: Date,
    default: Date.now
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Itinerary Schema
const itinerarySchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  title: {
    type: String,
    required: true,
    trim: true
  },
  destination: {
    type: String,
    required: true
  },
  startDate: {
    type: Date,
    required: true
  },
  endDate: {
    type: Date,
    required: true
  },
  duration: String,
  totalBudget: Number,
  estimatedCost: String,
  travelers: {
    type: Number,
    default: 1
  },
  interests: [String],
  accommodationType: String,
  transportationType: String,
  itinerary: {
    type: mongoose.Schema.Types.Mixed,
    required: true
  },
  additionalTips: [String],
  notes: String,
  rating: {
    type: Number,
    min: 1,
    max: 5
  },
  status: {
    type: String,
    enum: ['draft', 'completed', 'cancelled'],
    default: 'draft'
  },
  isPublic: {
    type: Boolean,
    default: false
  },
  tags: [String],
  metadata: {
    downloaded: {
      type: Number,
      default: 0
    },
    views: {
      type: Number,
      default: 0
    }
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

// Hash password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const saltRounds = 12;
    this.password = await bcrypt.hash(this.password, saltRounds);
    next();
  } catch (error) {
    next(error);
  }
});

// Update timestamp before saving itinerary
itinerarySchema.pre('save', function(next) {
  this.updatedAt = new Date();
  next();
});

// Create models
const User = mongoose.model('User', userSchema);
const Itinerary = mongoose.model('Itinerary', itinerarySchema);

// Database connection functions
const database = {
  async connect(mongoUri) {
    try {
      if (isConnected) {
        console.log('Already connected to MongoDB Atlas');
        return;
      }

      const options = {
        useNewUrlParser: true,
        useUnifiedTopology: true,
        serverSelectionTimeoutMS: 10000,
        socketTimeoutMS: 45000,
        maxPoolSize: 10,
        minPoolSize: 2,
        maxIdleTimeMS: 30000,
        retryWrites: true,
        w: 'majority'
      };

      await mongoose.connect(mongoUri, options);
      
      isConnected = true;
      console.log('✅ Successfully connected to MongoDB Atlas');
      
      // Handle connection events
      mongoose.connection.on('error', (error) => {
        console.error('❌ MongoDB connection error:', error);
        isConnected = false;
      });

      mongoose.connection.on('disconnected', () => {
        console.log('⚠️ MongoDB disconnected');
        isConnected = false;
      });

      mongoose.connection.on('reconnected', () => {
        console.log('✅ MongoDB reconnected');
        isConnected = true;
      });

    } catch (error) {
      console.error('❌ Failed to connect to MongoDB Atlas:', error);
      isConnected = false;
      throw error;
    }
  },

  async disconnect() {
    try {
      if (!isConnected) return;
      
      await mongoose.disconnect();
      isConnected = false;
      console.log('✅ Disconnected from MongoDB Atlas');
    } catch (error) {
      console.error('❌ Error disconnecting from MongoDB:', error);
      throw error;
    }
  },

  isConnected() {
    return isConnected && mongoose.connection.readyState === 1;
  },

  getConnectionStatus() {
    if (!isConnected) return 'Disconnected';
    
    switch (mongoose.connection.readyState) {
      case 0: return 'Disconnected';
      case 1: return 'Connected';
      case 2: return 'Connecting';
      case 3: return 'Disconnecting';
      default: return 'Unknown';
    }
  }
};

// Helper function to validate ObjectId
function validateAndConvertId(id) {
  if (!mongoose.Types.ObjectId.isValid(id)) {
    throw new Error('Invalid ID format');
  }
  return new mongoose.Types.ObjectId(id);
}

// User database operations
const userDB = {
  User,

  async createUser(userData) {
    try {
      // Check if user already exists
      const existingUser = await User.findOne({
        $or: [
          { email: userData.email },
          { username: userData.username }
        ]
      });

      if (existingUser) {
        if (existingUser.email === userData.email) {
          throw new Error('Email already registered');
        }
        if (existingUser.username === userData.username) {
          throw new Error('Username already taken');
        }
      }

      const user = new User(userData);
      await user.save();
      
      // Return user without password
      const userObj = user.toObject();
      delete userObj.password;
      return userObj;
    } catch (error) {
      if (error.code === 11000) {
        const field = Object.keys(error.keyPattern)[0];
        throw new Error(`${field} already exists`);
      }
      throw error;
    }
  },

  async authenticateUser(email, password) {
    try {
      const user = await User.findOne({ email });
      if (!user) {
        throw new Error('Invalid credentials');
      }

      const isValidPassword = await bcrypt.compare(password, user.password);
      if (!isValidPassword) {
        throw new Error('Invalid credentials');
      }

      // Update last login
      user.lastLogin = new Date();
      await user.save();

      // Return user without password
      const userObj = user.toObject();
      delete userObj.password;
      return userObj;
    } catch (error) {
      throw error;
    }
  },

  async getUserById(userId) {
    try {
      const objectId = validateAndConvertId(userId);
      const user = await User.findById(objectId).select('-password');
      
      if (!user) {
        throw new Error('User not found');
      }
      
      return user.toObject();
    } catch (error) {
      throw error;
    }
  },

  async updateUser(userId, updateData) {
    try {
      const objectId = validateAndConvertId(userId);
      const user = await User.findByIdAndUpdate(
        objectId,
        updateData,
        { new: true, select: '-password' }
      );
      
      if (!user) {
        throw new Error('User not found');
      }
      
      return user.toObject();
    } catch (error) {
      throw error;
    }
  },

  async changePassword(userId, currentPassword, newPassword) {
    try {
      const objectId = validateAndConvertId(userId);
      const user = await User.findById(objectId);
      
      if (!user) {
        throw new Error('User not found');
      }

      const isValidPassword = await bcrypt.compare(currentPassword, user.password);
      if (!isValidPassword) {
        throw new Error('Current password is incorrect');
      }

      user.password = newPassword;
      await user.save();

      return { message: 'Password changed successfully' };
    } catch (error) {
      throw error;
    }
  },

  async deleteUser(userId) {
    try {
      const objectId = validateAndConvertId(userId);
      
      // Delete all user's itineraries first
      await Itinerary.deleteMany({ userId: objectId });
      
      // Delete user
      const user = await User.findByIdAndDelete(objectId);
      
      if (!user) {
        throw new Error('User not found');
      }

      return { message: 'Account deleted successfully' };
    } catch (error) {
      throw error;
    }
  },

  async getUserStats(userId) {
    try {
      const objectId = validateAndConvertId(userId);
      
      const user = await User.findById(objectId);
      if (!user) {
        throw new Error('User not found');
      }

      const itineraryCount = await Itinerary.countDocuments({ userId: objectId });
      const totalDownloads = await Itinerary.aggregate([
        { $match: { userId: objectId } },
        { $group: { _id: null, total: { $sum: '$metadata.downloaded' } } }
      ]);

      return {
        totalTrips: itineraryCount,
        totalDownloads: totalDownloads[0]?.total || 0,
        memberSince: user.createdAt,
        lastLogin: user.lastLogin
      };
    } catch (error) {
      throw error;
    }
  }
};

// Itinerary database operations
const itineraryDB = {
  Itinerary,

  async saveItinerary(userId, itineraryData) {
    try {
      const objectId = validateAndConvertId(userId);
      
      const itinerary = new Itinerary({
        ...itineraryData,
        userId: objectId
      });
      
      await itinerary.save();
      return itinerary.toObject();
    } catch (error) {
      throw error;
    }
  },

  async getUserItineraries(userId, options = {}) {
    try {
      const objectId = validateAndConvertId(userId);
      const { page = 1, limit = 10, sortBy = 'createdAt', sortOrder = 'desc' } = options;
      
      const sort = {};
      sort[sortBy] = sortOrder === 'desc' ? -1 : 1;
      
      const skip = (page - 1) * limit;
      
      const query = { userId: objectId };
      if (options.status) query.status = options.status;
      if (options.destination) query.destination = new RegExp(options.destination, 'i');
      
      const itineraries = await Itinerary.find(query)
        .sort(sort)
        .skip(skip)
        .limit(limit)
        .lean();
      
      const total = await Itinerary.countDocuments(query);
      
      return {
        itineraries,
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit)
        }
      };
    } catch (error) {
      throw error;
    }
  },

  async getItineraryById(itineraryId, userId) {
    try {
      const itineraryObjectId = validateAndConvertId(itineraryId);
      const userObjectId = validateAndConvertId(userId);
      
      const itinerary = await Itinerary.findOne({
        _id: itineraryObjectId,
        userId: userObjectId
      }).lean();
      
      if (!itinerary) {
        throw new Error('Itinerary not found or access denied');
      }
      
      // Increment view count
      await Itinerary.findByIdAndUpdate(itineraryObjectId, {
        $inc: { 'metadata.views': 1 }
      });
      
      return itinerary;
    } catch (error) {
      throw error;
    }
  },

  async updateItinerary(itineraryId, userId, updateData) {
    try {
      const itineraryObjectId = validateAndConvertId(itineraryId);
      const userObjectId = validateAndConvertId(userId);
      
      const itinerary = await Itinerary.findOneAndUpdate(
        { _id: itineraryObjectId, userId: userObjectId },
        updateData,
        { new: true }
      ).lean();
      
      if (!itinerary) {
        throw new Error('Itinerary not found or access denied');
      }
      
      return itinerary;
    } catch (error) {
      throw error;
    }
  },

  async deleteItinerary(itineraryId, userId) {
    try {
      const itineraryObjectId = validateAndConvertId(itineraryId);
      const userObjectId = validateAndConvertId(userId);
      
      const itinerary = await Itinerary.findOneAndDelete({
        _id: itineraryObjectId,
        userId: userObjectId
      });
      
      if (!itinerary) {
        throw new Error('Itinerary not found or access denied');
      }
      
      return { message: 'Trip deleted successfully' };
    } catch (error) {
      throw error;
    }
  },

  async searchItineraries(userId, searchTerm, options = {}) {
    try {
      const objectId = validateAndConvertId(userId);
      const { page = 1, limit = 10, sortBy = 'createdAt', sortOrder = 'desc' } = options;
      
      const sort = {};
      sort[sortBy] = sortOrder === 'desc' ? -1 : 1;
      
      const skip = (page - 1) * limit;
      
      const query = {
        userId: objectId,
        $or: [
          { title: new RegExp(searchTerm, 'i') },
          { destination: new RegExp(searchTerm, 'i') },
          { notes: new RegExp(searchTerm, 'i') },
          { tags: { $in: [new RegExp(searchTerm, 'i')] } }
        ]
      };
      
      const itineraries = await Itinerary.find(query)
        .sort(sort)
        .skip(skip)
        .limit(limit)
        .lean();
      
      const total = await Itinerary.countDocuments(query);
      
      return {
        itineraries,
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit)
        },
        searchTerm
      };
    } catch (error) {
      throw error;
    }
  },

  async getItineraryStats(userId) {
    try {
      const objectId = validateAndConvertId(userId);
      
      const stats = await Itinerary.aggregate([
        { $match: { userId: objectId } },
        {
          $group: {
            _id: null,
            totalTrips: { $sum: 1 },
            totalDownloads: { $sum: '$metadata.downloaded' },
            totalViews: { $sum: '$metadata.views' },
            averageRating: { $avg: '$rating' },
            totalBudget: { $sum: '$totalBudget' }
          }
        }
      ]);
      
      const statusStats = await Itinerary.aggregate([
        { $match: { userId: objectId } },
        { $group: { _id: '$status', count: { $sum: 1 } } }
      ]);
      
      const destinationStats = await Itinerary.aggregate([
        { $match: { userId: objectId } },
        { $group: { _id: '$destination', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 5 }
      ]);
      
      return {
        overview: stats[0] || {
          totalTrips: 0,
          totalDownloads: 0,
          totalViews: 0,
          averageRating: 0,
          totalBudget: 0
        },
        byStatus: statusStats,
        topDestinations: destinationStats
      };
    } catch (error) {
      throw error;
    }
  }
};

module.exports = {
  database,
  userDB,
  itineraryDB,
  validateAndConvertId
};