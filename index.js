const express = require('express');
const cors = require('cors');
const jwt = require("jsonwebtoken");
const { MongoClient, ServerApiVersion } = require('mongodb');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(cors({
    origin: [
        'http://localhost:5173',
    ]
}));
app.use(express.json());

// MongoDB Atlas URI
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.euq4zn2.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// MongoDB Client
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

// Connect to MongoDB
async function connectDB() {
    try {
        await client.connect();
        console.log("Connected to MongoDB Atlas");
    } catch (err) {
        console.error("Failed to connect to MongoDB Atlas", err);
    }
}
connectDB();

// User Collection
let userCollection;
client.connect().then(() => {
    userCollection = client.db("scicTask").collection("users");
}).catch(err => {
    console.error("Failed to initialize user collection", err);
});

// JWT Secret Key
const JWT_SECRET = process.env.JWT_SECRET || 'default_jwt_secret'; // Replace with your actual secret

// JWT Token Generator
function generateToken(user) {
    return jwt.sign(user, JWT_SECRET, { expiresIn: '6h' });
}

// Middleware to Verify JWT Token
function verifyToken(req, res, next) {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) {
        return res.status(401).json({ message: "Unauthorized: No token provided" });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: "Unauthorized: Invalid token" });
        }
        req.user = decoded;
        next();
    });
}

// Registration Endpoint
app.post('/register', async (req, res) => {
    const { name, pin, mobileNumber, email } = req.body;
    try {
        const hashedPin = await bcrypt.hash(pin, 10);
        const newUser = {
            name,
            pin: hashedPin,
            mobileNumber,
            email,
            status: 'pending',
            balance: 0,
            createdAt: new Date()
        };
        const result = await userCollection.insertOne(newUser);
        res.status(201).json({ message: 'User registered successfully, awaiting admin approval' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Login Endpoint
app.post('/login', async (req, res) => {
    const { identifier, pin } = req.body; // identifier can be mobileNumber or email
    try {
        const user = await userCollection.findOne({
            $or: [{ mobileNumber: identifier }, { email: identifier }]
        });
        if (!user) {
            return res.status(400).json({ message: 'User not found' });
        }

        const isMatch = await bcrypt.compare(pin, user.pin);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        const token = generateToken({ id: user._id });
        res.json({ token, user });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Ping Endpoint
app.get('/', (req, res) => {
    res.send('Server is running');
});

// Start the server
app.listen(port, () => {
    console.log(`Server is running on port: ${port}`);
});
