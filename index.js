import cookieParser from 'cookie-parser';
import cors from 'cors'; // Importing CORS middleware
import dotenv from 'dotenv'; // Importing dotenv to load environment variables from a .env file
import express from 'express'; // Importing the Express framework

// import all routes
import userRoutes from './routes/auth.routes.js';

dotenv.config();
const app = express();
const port = process.env.PORT || 3000;

// Corrected: Invoke cookieParser() properly
app.use(cookieParser());

// CORS Configuration
app.use(
  cors({
    origin: process.env.BASE_URL, // Allowing requests only from the specified frontend origin
    methods: ['GET', 'POST', 'DELETE', 'OPTIONS'], // Specifying the allowed HTTP methods
    allowedHeaders: ['Content-Type', 'Authorization'], // Defining the allowed request headers
  })
);

// Middleware to parse incoming JSON requests
app.use(express.json());

// Middleware to parse incoming form data (extended: true allows nested objects)
app.use(express.urlencoded({ extended: true }));

// Sample route
app.get('/', (req, res) => {
  res.send('Hello World!');
});

app.use('/api/v1/users', userRoutes);
// Start the server
app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
