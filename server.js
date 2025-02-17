const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const { Schema } = mongoose;
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require("multer");
const path = require("path");
const stripe = require('stripe')("pk_test_51L7nq8GOhLaGDHrEc7mIskYioo0z3BPrhlH5GHsGeCjnTW0XHMxOPha3ZsnlgaRCD6LJe0iqqTDWPNv7x4TSEMUW002abkOl96"); 

// Create express app and HTTP server
const app = express();
app.use(cors({ origin: '*' }));
app.use(express.json());
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: '*',
    }
});



// MongoDB connection
mongoose.connect('mongodb+srv://Ace001:1234AsEn@shadav.sxkowtq.mongodb.net/chatApp')
    .then(() => console.log("Connected to MongoDB"))
    .catch((err) => console.log(err));

// Create a user schema
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);

// Set up storage for uploaded files
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, "uploads/"); // Save uploaded files to 'uploads' directory
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname)); // Unique file name
    },
});


const upload = multer({ storage: storage });

app.post("/upload", upload.single("file"), (req, res) => {
    if (!req.file) {
        return res.status(400).send("No file uploaded.");
    }

    const fileUrl = `/uploads/${req.file.filename}`; // Construct the file URL

    // Send the URL back to the client
    res.json({ fileUrl });
});

// Set up the public folder to serve static files
app.use("/uploads", express.static("uploads"));

// Register a new user
app.post('/register', async (req, res) => {
    console.log(req.body);
    const { username, email, password } = req.body;

    try {
        // Check if the user already exists
        const userExists = await User.findOne({ email });
        if (userExists) {
            return res.status(400).json({ message: 'User already exists' });
        }

        // Hash the password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create new user
        const newUser = new User({
            username,
            email,
            password: hashedPassword,
        });

        // Save the user
        await newUser.save();

        // Generate a JWT token
        const token = jwt.sign({ id: newUser._id }, 'secretKey', { expiresIn: '1h' });

        res.status(201).json({
            message: 'User registered successfully',
            token,
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
    }
});

// Login a user
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'User not found' });
        }

        // Check if password matches
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        // Generate JWT token
        const token = jwt.sign({ id: user._id }, 'secretKey', { expiresIn: '1h' });

        res.json({
            message: 'Login successful',
            user: user.username,
            token,
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get all chat users with their latest messages
app.get('/chat-users', async (req, res) => {
    try {
        // Fetch all users
        const users = await User.find({}, 'username email'); // Only return username and email
        const chatUsers = await Promise.all(users.map(async (user) => {
            // Fetch last message for each user (if exists)
            const lastMessage = await Message.findOne({ sender: user.username }).sort({ createdAt: -1 }).exec();

            return {
                name: user.username,
                message: lastMessage ? lastMessage.text : 'No messages yet',
                time: lastMessage ? lastMessage.createdAt.toISOString().split('T')[0] : 'No messages yet',
                unread: false,  // You can implement a way to track unread messages later
            };
        }));

        res.json(chatUsers);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
    }
});

// Define a schema for storing messages
const messageSchema = new Schema({
    sender: String,
    recipient: String,  // Add recipient field
    text: String,
    type: String,
    file: {
        name: String,
        url: String
    },
    product: {
        name: String,
        price: String
    },
    createdAt: { type: Date, default: Date.now }
});


const Message = mongoose.model('Message', messageSchema);

// Store user socket IDs to track connections
let users = {};

// Real-time connection event
io.on('connection', (socket) => {
    // Store user with their socket ID
    socket.on('register', (username) => {
        users[username] = socket.id;
    });

    // Handle sending a message
    socket.on('sendMessage', async (message) => {
        console.log('Message:', message);
        const newMessage = new Message({ ...message, recipient: message.recipient });  // Add recipient
        await newMessage.save();
        console.log('Message:', newMessage);
        // Broadcast message to the admin
        if (message.sender !== 'admin') {
            if (users['admin']) {
                io.to(users['admin']).emit('newMessage', message);
            }
        } else {
            if (users[message.receiver]) {
                io.to(users[message.receiver]).emit('newMessage', message);
            }
        }
    });
    // Server-side: Fetch all previous messages for a user (admin can request chat history)
    socket.on('getMessages', async (username) => {
        try {
            const messages = await Message.find({
                $or: [
                    { sender: 'admin', recipient: username },
                    { sender: username, recipient: 'admin' }
                ]
            }).sort({ createdAt: 1 });  // Sort messages by time
            socket.emit('messagesHistory', messages);
        } catch (error) {
            console.error("Error fetching messages:", error);
            socket.emit('messagesHistory', []);  // Send empty array in case of error
        }
    });

    socket.on("typing", (username) => {
        console.log(`${username} is typing...`);
        io.emit("userTyping", { username });
    });

    socket.on("stopTyping", (username) => {
        console.log(`${username} stopped typing...`);
        io.emit("userStopTyping", { username });
    });

    // Disconnect event
    socket.on('disconnect', () => {
        console.log('user disconnected');
    });
});

// Set up a basic Express route to serve the frontend (if applicable)
app.get('/', (req, res) => {
    res.send('Chat server is running');
});

app.post('/create-payment-intent', async (req, res) => {
    try {
        const { amount } = req.body; // Amount should be passed from the client-side (in cents)

        const paymentIntent = await stripe.paymentIntents.create({
            amount,
            currency: 'usd', // You can change this to your required currency
            payment_method_types: ['card'],
        });

        res.json({ clientSecret: paymentIntent.client_secret });
    } catch (error) {
        res.status(500).send({ error: error.message });
    }
});

// Start the server
server.listen(3001, () => {
    console.log('Server running on http://localhost:3001');
});
