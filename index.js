require('dotenv').config();

const express = require('express');
const app = express();
const cors = require('cors');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');

const port = process.env.PORT || 5000;

// CORS setup to allow credentials (cookies)
app.use(cors({
    origin: [
        'http://localhost:3000',
        'http://127.0.0.1:3000',
        'https://hero-b13-a09-client-bzxs.vercel.app'
    ],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());
app.use(cookieParser());

const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

// Helper cookie options
const cookieOptions = {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
};

// Middleware to verify JWT Token
const verifyToken = (req, res, next) => {
    let token = req.cookies?.token;
    
    // Fallback to headers
    if (!token && req.headers.authorization) {
        token = req.headers.authorization.split(' ')[1];
    }
    
    if (!token) {
        return res.status(401).send({ message: 'unauthorized access' });
    }
    
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).send({ message: 'forbidden access' });
        }
        req.decoded = decoded;
        next();
    });
};

const run = async () => {
    try {
        // Connect the client to the server
        await client.connect();
        console.log("Connected to MongoDB successfully!");

        const db = client.db('ph-13-a09');
        const usersCollection = db.collection('users');
        const carsCollection = db.collection('cars');
        const bookingsCollection = db.collection('bookings');

        // ================= AUTH ENDPOINTS =================

        // Register User
        app.post('/api/auth/register', async (req, res) => {
            try {
                const { name, email, photoUrl, password } = req.body;
                
                if (!name || !email || !password) {
                    return res.status(400).send({ success: false, message: 'Missing required fields' });
                }

                // Password strength validation
                const hasUpper = /[A-Z]/.test(password);
                const hasLower = /[a-z]/.test(password);
                const isLongEnough = password.length >= 6;

                if (!hasUpper || !hasLower || !isLongEnough) {
                    return res.status(400).send({ 
                        success: false, 
                        message: 'Password must have an uppercase letter, a lowercase letter, and be at least 6 characters.' 
                    });
                }

                const existingUser = await usersCollection.findOne({ email });
                if (existingUser) {
                    return res.status(400).send({ success: false, message: 'User already exists' });
                }

                const hashedPassword = await bcrypt.hash(password, 10);
                const newUser = {
                    name,
                    email,
                    photoUrl: photoUrl || '',
                    password: hashedPassword,
                    createdAt: new Date()
                };

                await usersCollection.insertOne(newUser);
                res.status(201).send({ success: true, message: 'Registration successful' });
            } catch (error) {
                console.error(error);
                res.status(500).send({ success: false, message: 'Internal server error' });
            }
        });

        // Login User
        app.post('/api/auth/login', async (req, res) => {
            try {
                const { email, password } = req.body;

                if (!email || !password) {
                    return res.status(400).send({ success: false, message: 'Missing credentials' });
                }

                const user = await usersCollection.findOne({ email });
                if (!user) {
                    return res.status(400).send({ success: false, message: 'Invalid email or password' });
                }

                const isMatch = await bcrypt.compare(password, user.password);
                if (!isMatch) {
                    return res.status(400).send({ success: false, message: 'Invalid email or password' });
                }

                const token = jwt.sign(
                    { email: user.email, name: user.name }, 
                    process.env.JWT_SECRET, 
                    { expiresIn: '7d' }
                );

                res.cookie('token', token, cookieOptions);
                res.send({ 
                    success: true, 
                    user: { name: user.name, email: user.email, photoUrl: user.photoUrl } 
                });
            } catch (error) {
                console.error(error);
                res.status(500).send({ success: false, message: 'Internal server error' });
            }
        });

        // Google Authentication Login/Upsert
        app.post('/api/auth/google', async (req, res) => {
            try {
                const { name, email, photoUrl } = req.body;

                if (!email) {
                    return res.status(400).send({ success: false, message: 'Email is required' });
                }

                let user = await usersCollection.findOne({ email });
                if (!user) {
                    user = {
                        name: name || 'Google User',
                        email,
                        photoUrl: photoUrl || '',
                        createdAt: new Date()
                    };
                    await usersCollection.insertOne(user);
                }

                const token = jwt.sign(
                    { email: user.email, name: user.name }, 
                    process.env.JWT_SECRET, 
                    { expiresIn: '7d' }
                );

                res.cookie('token', token, cookieOptions);
                res.send({ 
                    success: true, 
                    user: { name: user.name, email: user.email, photoUrl: user.photoUrl } 
                });
            } catch (error) {
                console.error(error);
                res.status(500).send({ success: false, message: 'Internal server error' });
            }
        });

        // Logout User
        app.post('/api/auth/logout', (req, res) => {
            res.clearCookie('token', { 
                ...cookieOptions, 
                maxAge: 0 
            });
            res.send({ success: true, message: 'Logged out successfully' });
        });

        // Get Current User Profile
        app.get('/api/auth/me', async (req, res) => {
            let token = req.cookies?.token;
            if (!token && req.headers.authorization) {
                token = req.headers.authorization.split(' ')[1];
            }

            if (!token) {
                return res.send({ user: null });
            }

            try {
                const decoded = jwt.verify(token, process.env.JWT_SECRET);
                const user = await usersCollection.findOne({ email: decoded.email });
                if (!user) {
                    return res.send({ user: null });
                }

                res.send({
                    user: {
                        name: user.name,
                        email: user.email,
                        photoUrl: user.photoUrl
                    }
                });
            } catch (err) {
                res.send({ user: null });
            }
        });


        // ================= CARS ENDPOINTS =================

        // Create Car Listing (Private)
        app.post('/api/cars', verifyToken, async (req, res) => {
            try {
                const { name, price, type, image, seatCapacity, location, description, availability } = req.body;
                
                if (!name || !price || !type || !image || !seatCapacity || !location) {
                    return res.status(400).send({ success: false, message: 'Missing required car fields' });
                }

                const newCar = {
                    name,
                    price: Number(price),
                    type,
                    image,
                    seatCapacity: Number(seatCapacity),
                    location,
                    description: description || '',
                    availability: availability === undefined ? true : Boolean(availability),
                    ownerEmail: req.decoded.email,
                    ownerName: req.decoded.name,
                    bookingCount: 0,
                    createdAt: new Date()
                };

                const result = await carsCollection.insertOne(newCar);
                res.status(201).send({ success: true, carId: result.insertedId, message: 'Car listing created' });
            } catch (error) {
                console.error(error);
                res.status(500).send({ success: false, message: 'Internal server error' });
            }
        });

        // Get All Cars (Public - with Search and Type Filter)
        app.get('/api/cars', async (req, res) => {
            try {
                const { search, type } = req.query;
                
                let query = {};
                
                if (search) {
                    query.name = { $regex: search, $options: 'i' };
                }

                if (type) {
                    query.type = type;
                }

                const cars = await carsCollection.find(query).sort({ createdAt: -1 }).toArray();
                res.send(cars);
            } catch (error) {
                console.error(error);
                res.status(500).send({ message: 'Internal server error' });
            }
        });

        // Get Logged In User's Cars (Private)
        app.get('/api/my-cars', verifyToken, async (req, res) => {
            try {
                const cars = await carsCollection.find({ ownerEmail: req.decoded.email }).sort({ createdAt: -1 }).toArray();
                res.send(cars);
            } catch (error) {
                console.error(error);
                res.status(500).send({ message: 'Internal server error' });
            }
        });

        // Get Single Car by ID (Public)
        app.get('/api/cars/:id', async (req, res) => {
            try {
                const id = req.params.id;
                
                if (!ObjectId.isValid(id)) {
                    return res.status(400).send({ message: 'Invalid ID format' });
                }

                const car = await carsCollection.findOne({ _id: new ObjectId(id) });
                if (!car) {
                    return res.status(404).send({ message: 'Car not found' });
                }

                res.send(car);
            } catch (error) {
                console.error(error);
                res.status(500).send({ message: 'Internal server error' });
            }
        });

        // Update Car Listing (Private)
        app.put('/api/cars/:id', verifyToken, async (req, res) => {
            try {
                const id = req.params.id;
                const { name, price, type, image, seatCapacity, location, description, availability } = req.body;

                if (!ObjectId.isValid(id)) {
                    return res.status(400).send({ success: false, message: 'Invalid ID format' });
                }

                const car = await carsCollection.findOne({ _id: new ObjectId(id) });
                if (!car) {
                    return res.status(404).send({ success: false, message: 'Car not found' });
                }

                // Verify Owner
                if (car.ownerEmail !== req.decoded.email) {
                    return res.status(403).send({ success: false, message: 'Access denied: You do not own this listing' });
                }

                const updateDoc = {
                    $set: {
                        name: name || car.name,
                        price: price !== undefined ? Number(price) : car.price,
                        type: type || car.type,
                        image: image || car.image,
                        seatCapacity: seatCapacity !== undefined ? Number(seatCapacity) : car.seatCapacity,
                        location: location || car.location,
                        description: description !== undefined ? description : car.description,
                        availability: availability !== undefined ? Boolean(availability) : car.availability
                    }
                };

                await carsCollection.updateOne({ _id: new ObjectId(id) }, updateDoc);
                res.send({ success: true, message: 'Car listing updated successfully' });
            } catch (error) {
                console.error(error);
                res.status(500).send({ success: false, message: 'Internal server error' });
            }
        });

        // Delete Car Listing (Private)
        app.delete('/api/cars/:id', verifyToken, async (req, res) => {
            try {
                const id = req.params.id;

                if (!ObjectId.isValid(id)) {
                    return res.status(400).send({ success: false, message: 'Invalid ID format' });
                }

                const car = await carsCollection.findOne({ _id: new ObjectId(id) });
                if (!car) {
                    return res.status(404).send({ success: false, message: 'Car not found' });
                }

                // Verify Owner
                if (car.ownerEmail !== req.decoded.email) {
                    return res.status(403).send({ success: false, message: 'Access denied: You do not own this listing' });
                }

                await carsCollection.deleteOne({ _id: new ObjectId(id) });
                res.send({ success: true, message: 'Car listing deleted successfully' });
            } catch (error) {
                console.error(error);
                res.status(500).send({ success: false, message: 'Internal server error' });
            }
        });


        // ================= BOOKINGS ENDPOINTS =================

        // Create Booking (Private)
        app.post('/api/bookings', verifyToken, async (req, res) => {
            try {
                const { carId, startDate, endDate, driverNeeded, specialNote } = req.body;

                if (!carId || !startDate || !endDate) {
                    return res.status(400).send({ success: false, message: 'Missing booking dates or car ID' });
                }

                if (!ObjectId.isValid(carId)) {
                    return res.status(400).send({ success: false, message: 'Invalid Car ID format' });
                }

                const car = await carsCollection.findOne({ _id: new ObjectId(carId) });
                if (!car) {
                    return res.status(404).send({ success: false, message: 'Car not found' });
                }

                if (!car.availability) {
                    return res.status(400).send({ success: false, message: 'Car is currently unavailable' });
                }

                // Calculate total price based on date duration
                const start = new Date(startDate);
                const end = new Date(endDate);
                
                if (start >= end) {
                    return res.status(400).send({ success: false, message: 'Start date must be before end date' });
                }

                const diffTime = Math.abs(end - start);
                const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24)) || 1;
                const totalPrice = diffDays * car.price;

                const newBooking = {
                    carId: new ObjectId(carId),
                    carName: car.name,
                    carImage: car.image,
                    dailyPrice: car.price,
                    userEmail: req.decoded.email,
                    userName: req.decoded.name,
                    startDate,
                    endDate,
                    driverNeeded: Boolean(driverNeeded),
                    specialNote: specialNote || '',
                    totalPrice,
                    status: 'Confirmed',
                    bookingDate: new Date(),
                    createdAt: new Date()
                };

                const result = await bookingsCollection.insertOne(newBooking);

                // Increment bookingCount for this car
                await carsCollection.updateOne(
                    { _id: new ObjectId(carId) },
                    { $inc: { bookingCount: 1 } }
                );

                res.status(201).send({ 
                    success: true, 
                    bookingId: result.insertedId, 
                    totalPrice, 
                    message: 'Booking confirmed successfully' 
                });
            } catch (error) {
                console.error(error);
                res.status(500).send({ success: false, message: 'Internal server error' });
            }
        });

        // Get Logged In User's Bookings (Private)
        app.get('/api/my-bookings', verifyToken, async (req, res) => {
            try {
                const bookings = await bookingsCollection.find({ userEmail: req.decoded.email }).sort({ createdAt: -1 }).toArray();
                res.send(bookings);
            } catch (error) {
                console.error(error);
                res.status(500).send({ message: 'Internal server error' });
            }
        });

        // Cancel Booking (Private - user can only cancel their own)
        app.delete('/api/bookings/:id', verifyToken, async (req, res) => {
            try {
                const id = req.params.id;

                if (!ObjectId.isValid(id)) {
                    return res.status(400).send({ success: false, message: 'Invalid booking ID format' });
                }

                const booking = await bookingsCollection.findOne({ _id: new ObjectId(id) });
                if (!booking) {
                    return res.status(404).send({ success: false, message: 'Booking not found' });
                }

                // Verify ownership
                if (booking.userEmail !== req.decoded.email) {
                    return res.status(403).send({ success: false, message: 'Access denied: You do not own this booking' });
                }

                await bookingsCollection.deleteOne({ _id: new ObjectId(id) });

                // Decrement bookingCount for the car
                if (booking.carId) {
                    await carsCollection.updateOne(
                        { _id: new ObjectId(booking.carId) },
                        { $inc: { bookingCount: -1 } }
                    );
                }

                res.send({ success: true, message: 'Booking cancelled successfully' });
            } catch (error) {
                console.error(error);
                res.status(500).send({ success: false, message: 'Internal server error' });
            }
        });

        // ================= STATS ENDPOINT =================

        // Get Platform Stats (Public)
        app.get('/api/stats', async (req, res) => {
            try {
                const [totalCars, totalBookings, totalUsers] = await Promise.all([
                    carsCollection.countDocuments(),
                    bookingsCollection.countDocuments(),
                    usersCollection.countDocuments()
                ]);
                res.send({ totalCars, totalBookings, totalUsers });
            } catch (error) {
                console.error(error);
                res.status(500).send({ message: 'Internal server error' });
            }
        });

    } catch (e) {
        console.error("Error running server:", e);
    }
}
run().catch(console.dir);


app.get('/', (req, res) => {
    res.send('DriveFleet API Server is running');
});

// Keep connection open and start listening
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});

module.exports = app;
