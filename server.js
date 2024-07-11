const express = require('express');
const products = require('./top.js');
const product = require('./product.js');
const details = require('./details.js');
const url = require('url');
const db = require('./database');
const querystring = require('querystring');
//const userss = require('./users.js');
const session = require('express-session');
const ejs = require('ejs');
const QRCode = require('qrcode');
const http = require('http');
const Busboy = require('busboy');
const sha1 = require('sha1');
const path = require('path');
const paypal = require('@paypal/checkout-server-sdk');
const fs = require('fs');
const crypto = require('crypto');
const { Scene, PerspectiveCamera, WebGLRenderer, PlaneGeometry, MeshBasicMaterial, TextureLoader, Mesh } = require('three');
const bodyParser = require('body-parser');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const app = express();
// Set EJS as view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views')); // Add this line


const PORT = process.env.PORT || 3000;

app.use(express.json());
// Serve static files from the 'public' directory
app.use(express.static('public'));

// Middleware to parse incoming request bodies
app.use(bodyParser.urlencoded({ extended: true }));

// Middleware to parse JSON bodies
app.use(bodyParser.json());


// Middleware for session management
app.use(session({
  secret: 'aQjK!#n3rP5v&mB^9H@LwDyUz$EXe8Gs', // Change this to a secure random key
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());



const server = http.createServer((req, res) => {
  if (req.method === "POST") {
    upload(req, (err, result) => {
      if (err) {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: err }));
      } else {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(result));
      }
    });
  } else {
    res.writeHead(404);
    res.end();
  }
});



 // Simulate a cart for demonstration
    const cart = [];

// PayPal client configuration
const clientId = 'AbX7BIpyZUUeELY_y0ldeq-cQYjTzItKcsb8PmRZzNwW4tkFbKhZ_kkeyINwDMND7vFpM9Wsfzufh2Va';

const clientSecret = 'EK8eYc4LLVWuEChMiniQh-Kqz1kDBQIHQOUbckWoN1-WDxHl7zAw9kS_oO6-cesqN0kCaYsj9FQL4xOT';

// Set up PayPal environment
const environment = new paypal.core.SandboxEnvironment(clientId, clientSecret);
const client = new paypal.core.PayPalHttpClient(environment);

// Middleware for creating an order
async function createOrderMiddleware(req, res, next) {
  const request = new paypal.orders.OrdersCreateRequest();
  request.prefer('return=representation');
  request.requestBody({
    intent: 'CAPTURE',
    purchase_units: [{
      amount: {
        currency_code: 'USD',
        value: '100.00' // Adjust this value as needed
      }
    }]
  });

  try {
    const response = await client.execute(request);
    console.log('Order created:', response.result);
    req.orderId = response.result.id; // Store the order ID in the request object
    next();
  } catch (error) {
    console.error('Error creating order:', error);
    res.status(500).send('Error creating order');
  }
}

// Middleware for capturing an order
async function captureOrderMiddleware(req, res, next) {
  const orderId = req.orderId; // Retrieve the order ID from the request object

  if (!orderId) {
    return res.status(400).send('Order ID not found');
  }

  const request = new paypal.orders.OrdersCaptureRequest(orderId);
  request.requestBody({});

  try {
    const response = await client.execute(request);
    console.log('Order captured:', response.result);
    req.paymentStatus = response.result.status === 'COMPLETED'; // Store the payment status in the request object
    next();
  } catch (error) {
    console.error('Error capturing order:', error);
    res.status(500).send('Error capturing order');
  }
}

// Example usage: Route handler
app.post('/checkout', createOrderMiddleware, captureOrderMiddleware, (req, res) => {
  const paymentStatus = req.paymentStatus; // Retrieve the payment status from the request object

  if (paymentStatus) {
    res.send('Payment successful');
  } else {
    res.send('Payment failed');
  }
}); 


const users = [
  {
    id: 1,
    username: '',
    password: '',
    profilePic: '',
    wallet: {
      balance: 0,
      transactions: []
    },
    userId: '',
    resetToken: null,
    tokenExpiry: null
  },
  // Add more users as needed
];




// Configure Passport.js
passport.use(new LocalStrategy(
  (username, password, done) => {
    // Implement your authentication logic here
    // Example: Check if username and password are valid
    if (username === username && password === password) {
      return done(null, { id: 1, username: username });
    } else {
      return done(null, false, { message: 'Incorrect username or password' });
    }
  }
));  

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  // Fetch user from database based on id
  // Example: User.findById(id, (err, user) => done(err, user));
  done(null, { id: 1, username, phone, orderId, userId, country: 'admin' });
});



// Route to authenticate user
app.get('/payment', isAuthenticated, (req, res) => {
  res.send('Payment page');
});

app.post('/charge', isAuthenticated, async (req, res) => {
  // Handle payment processing with Stripe
  try {
    const paymentIntent = await stripe.paymentIntents.create({
      amount: 1000, // Amount in cents
      currency: 'usd',
      description: 'Example charge',
      payment_method: req.body.payment_method_id,
      confirm: true
    });
    // Payment successful
    res.send('Payment successful');
  } catch (error) {
    // Handle payment failure
    res.status(500).send('Payment failed');
  }
});

// Middleware to check if user is authenticated
function isAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/cart');
} 

// Dummy user data (replace this with actual user data and authentication logic)


app.get('/account', (req, res) => {
  const isAuthenticated = req.session.isAuthenticated || false;
  const user = req.session.user || null;

  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>User Account</title>
      <link rel="stylesheet" href="/styles.css">
    </head>
    <body>
      <h1>${user.username}'s Page</h1>
      ${isAuthenticated ? `<h2>Welcome, ${user.username}!</h2>` : '<p>You are not logged in.</p>'}
      
      <!-- Authentication buttons -->
      ${isAuthenticated ? 
        `<form action="/logout" method="POST">
           <button type="submit" id="logout" class="btn">Log Out</button>
         </form>` : 
        `<form action="/login" method="POST">
           <input type="text" name="username" placeholder="Username"><br><br>
           <input type="password" name="password" placeholder="Password"><br><br>
           <button type="submit" class="btn">Log In</button>
         </form>`
      }
      <a href="/signup"><h4>Sign up</h4></a>
      <br>
      <a href="/">Back to Home</a>

      <script>
        document.addEventListener('DOMContentLoaded', () => {
          const logoutButton = document.getElementById('logout');
          if (logoutButton) {
            logoutButton.addEventListener('click', (event) => {
              event.preventDefault();

              fetch('/logout', {
                method: 'POST',
                credentials: 'same-origin'
              })
              .then(response => {
                if (response.ok) {
                  localStorage.clear(); // Clear client-side data
                  window.location.href = '/account'; // Redirect to login or home page
                } else {
                  console.error('Logout failed');
                }
              })
              .catch(error => console.error('Error:', error));
            });
          }
        });

        function adjustColorsBasedOnTime() {
          const date = new Date();
          const hours = date.getHours();
          const body = document.body;

          if (hours >= 6 && hours < 18) { // Daytime (6am to 5:59pm)
            body.style.backgroundColor = "white";
            body.style.color = "black";
          } else { // Nighttime (6pm to 5:59am)
            body.style.backgroundColor = "black";
            body.style.color = "white";
          }
        }

        // Call the function when the page loads to adjust colors based on the time of day
        adjustColorsBasedOnTime();

        // Redirect after 5 seconds
        setTimeout(() => {
          window.location.href = '/';
        }, 5000);
      </script>
    </body>
    </html>
  `);
});


// Route for user login
// Login route
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  // Check if the provided username and password match any user
  const user = users.find(user => user.username === username && user.password === password);
  if (user) {
    // Set session variables to mark the user as authenticated and store user data
    req.session.isAuthenticated = true;
    req.session.user = user;
    res.redirect('/account');
  } else {
    res.status(401).send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>error</title>
      <link rel="stylesheet" href="/styles.css">
    </head>
    <body>
<h2>Invalid username or password  click the sign up button if you haven't created an account yet.</h2>
<br><br>
<a href="signup"><button class="btn">sign up</button></a>
<br><br>
<a href="/reset-password">FORGOT PASSWORD</a>
<script>
function adjustColorsBasedOnTime() {
    const date = new Date();
    const hours = date.getHours();
    const body = document.body;

    if (hours >= 6 && hours < 18) { // Daytime (6am to 5:59pm)
        body.style.backgroundColor = "white";
        body.style.color = "black";
    } else { // Nighttime (6pm to 5:59am)
        body.style.backgroundColor = "black";
        body.style.color = "white";
    }
}

// Call the function when the page loads to adjust colors based on the time of day
adjustColorsBasedOnTime();
</script>
    </body>
    </html>
  `);
  }
});



// Route to render password reset form
app.get('/reset-password', (req, res) => {
  res.send(`
  <!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Password</title>
    <link rel="stylesheet" href="/styles.css">
  </head>
  <body>
    <form action="/recover-password" method="post">
      <input type="text" name="username" placeholder="Username" required>
      <button type="submit" class="btn">Reset Password</button>
    </form>
<script>
function adjustColorsBasedOnTime() {
    const date = new Date();
    const hours = date.getHours();
    const body = document.body;

    if (hours >= 6 && hours < 18) { // Daytime (6am to 5:59pm)
        body.style.backgroundColor = "white";
        body.style.color = "black";
    } else { // Nighttime (6pm to 5:59am)
        body.style.backgroundColor = "black";
        body.style.color = "white";
    }
}

// Call the function when the page loads to adjust colors based on the time of day
adjustColorsBasedOnTime();
</script>
  </body>
  </html>
  `);
});



// Route for password recovery
app.post('/recover-password', (req, res) => {
  const { username } = req.body;
  const user = users.find(user => user.username === username);

  if (user) {
    // Generate a unique token
    const token = crypto.randomBytes(20).toString('hex');
    user.resetToken = token; // Store the token with the user for verification later
    user.tokenExpiry = Date.now() + 180000; // Token expiry set to 3 minutes (180,000 milliseconds)

    res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Password Recovery</title>
      <link rel="stylesheet" href="/styles.css">
      <script>
        function displayToken() {
          document.getElementById('token-popup').style.display = 'block';
          document.getElementById('generated-token').textContent = '${token}';
          
          // Set timeout to hide popup after 3 minutes (180,000 milliseconds)
          setTimeout(function() {
            document.getElementById('token-popup').style.display = 'none';
          }, 180000);
        }

function adjustColorsBasedOnTime() {
    const date = new Date();
    const hours = date.getHours();
    const body = document.body;

    if (hours >= 6 && hours < 18) { // Daytime (6am to 5:59pm)
        body.style.backgroundColor = "white";
        body.style.color = "black";
    } else { // Nighttime (6pm to 5:59am)
        body.style.backgroundColor = "black";
        body.style.color = "white";
    }
}

// Call the function when the page loads to adjust colors based on the time of day
adjustColorsBasedOnTime();
      </script>
    </head>
    <body>
      <button onclick="displayToken()" class="btn">Generate Token</button>
      <div id="token-popup" style="display: none; position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); background: #f0f0f0; padding: 20px; border: 1px solid #ccc;">
        <h2>Your password reset token is:</h2>
        <p id="generated-token"></p>
        <p>Please use this token to reset your password.</p>
        <form action="/verify-token" method="post">
          <input type="text" name="token" placeholder="Enter token" required>
          <input type="hidden" name="username" value="${username}">
<br>
          <button type="submit" class="btn">Verify Token</button>
        </form>
<br>
        <p>This popup will disappear in 3 minutes.</p>
      </div>
<script>
function adjustColorsBasedOnTime() {
    const date = new Date();
    const hours = date.getHours();
    const body = document.body;

    if (hours >= 6 && hours < 18) { // Daytime (6am to 5:59pm)
        body.style.backgroundColor = "white";
        body.style.color = "black";
    } else { // Nighttime (6pm to 5:59am)
        body.style.backgroundColor = "black";
        body.style.color = "white";
    }
}

// Call the function when the page loads to adjust colors based on the time of day
adjustColorsBasedOnTime();
</script>
    </body>
    </html>
    `);
  } else {
    res.status(404).send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>User Not Found</title>
      <link rel="stylesheet" href="/styles.css">
    </head>
    <body>
      <h2>User not found. Please check your username.</h2>
    </body>
<script>
function adjustColorsBasedOnTime() {
    const date = new Date();
    const hours = date.getHours();
    const body = document.body;

    if (hours >= 6 && hours < 18) { // Daytime (6am to 5:59pm)
        body.style.backgroundColor = "white";
        body.style.color = "black";
    } else { // Nighttime (6pm to 5:59am)
        body.style.backgroundColor = "black";
        body.style.color = "white";
    }
}

// Call the function when the page loads to adjust colors based on the time of day
adjustColorsBasedOnTime();
</script>
    </html>
    `);
  }
});


// Route to verify token and handle password reset
app.post('/verify-token', (req, res) => {
  const { username, token, newPassword } = req.body;
  const user = users.find(user => user.username === username);

  if (user && user.resetToken === token && Date.now() < user.tokenExpiry) {
    // Token is valid, proceed with password reset
    user.password = newPassword;

    // Clear/reset token and expiry after successful reset
    user.resetToken = null;
    user.tokenExpiry = null;

    res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Password Reset Successful</title>
      <link rel="stylesheet" href="/styles.css">
    </head>
    <body>
     <h2>Reset Your Password</h2>

      <form action="/set-password" method="post">
        <input type="hidden" name="username" value="${username}">
<br>
        <input type="password" name="newPassword" placeholder="Enter new password" required>
<br><br>
        <button type="submit" class="btn">Reset Password</button>
      </form>
<script>
function adjustColorsBasedOnTime() {
    const date = new Date();
    const hours = date.getHours();
    const body = document.body;

    if (hours >= 6 && hours < 18) { // Daytime (6am to 5:59pm)
        body.style.backgroundColor = "white";
        body.style.color = "black";
    } else { // Nighttime (6pm to 5:59am)
        body.style.backgroundColor = "black";
        body.style.color = "white";
    }
}

// Call the function when the page loads to adjust colors based on the time of day
adjustColorsBasedOnTime();
</script>
    </body>
    </html>
    `);
  } else {
    // Token is invalid or expired
    res.status(400).send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Invalid Token</title>
      <link rel="stylesheet" href="/styles.css">
    </head>
    <body>
      <h2>Invalid token or token expired. Please try again.</h2>
<script>
function adjustColorsBasedOnTime() {
    const date = new Date();
    const hours = date.getHours();
    const body = document.body;

    if (hours >= 6 && hours < 18) { // Daytime (6am to 5:59pm)
        body.style.backgroundColor = "white";
        body.style.color = "black";
    } else { // Nighttime (6pm to 5:59am)
        body.style.backgroundColor = "black";
        body.style.color = "white";
    }
}

// Call the function when the page loads to adjust colors based on the time of day
adjustColorsBasedOnTime();
</script>
    </body>
    </html>
    `);
  }
});



app.post('/set-password', (req, res) => {
  const { username, newPassword } = req.body;
  const user = users.find(user => user.username === username);

  if (user) {
    // Update the user's password
    user.password = newPassword;

    // Clear/reset token and expiry after successful reset
    user.resetToken = null;
    user.tokenExpiry = null;

    res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Password Reset Successful</title>
      <link rel="stylesheet" href="/styles.css">
    </head>
    <body>
      <h2>Password reset successful.</h2>
      <p>Your password has been updated.</p>
      <a href="/account">Go to Login Page</a>
    </body>
    </html>
    `);
  } else {
    res.status(400).send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Error</title>
      <link rel="stylesheet" href="/styles.css">
    </head>
    <body>
      <h2>Error resetting password. Please try again.</h2>
<script>
function adjustColorsBasedOnTime() {
    const date = new Date();
    const hours = date.getHours();
    const body = document.body;

    if (hours >= 6 && hours < 18) { // Daytime (6am to 5:59pm)
        body.style.backgroundColor = "white";
        body.style.color = "black";
    } else { // Nighttime (6pm to 5:59am)
        body.style.backgroundColor = "black";
        body.style.color = "white";
    }
}

// Call the function when the page loads to adjust colors based on the time of day
adjustColorsBasedOnTime();
</script>
    </body>
    </html>
    `);
  }
});



// Account route
app.get('/account', (req, res) => {
  // Check if the user is authenticated
  if (req.session.isAuthenticated) {
    // Render account page with user data
    res.send(`Welcome to your account, ${req.session.user.username}!`);
  } else {
    // Redirect to login page if not authenticated
    res.redirect('/login');
  }
});

// Route for user logout
app.post('/logout', (req, res) => {
  // Destroy the session to log out the user
  req.session.destroy((err) => {
    if (err) {
      console.error('Error destroying session:', err);
      res.status(500).send('Internal Server Error');
    } else {
      res.redirect('/account');
    }
  });
});

// Define route for the user sign-up page
app.get('/signup', (req, res) => {
  // Render the sign-up page HTML
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>User Sign-Up</title>
      <link rel="stylesheet" href="/styles.css">
    </head>
    <body>
      <h1>User Sign-Up Page</h1>
      <form action="/signup" method="POST">
        <input type="text" name="username" placeholder="Username"><br><br>
        <input type="password" name="password" id="pass"placeholder="Password"><br><br>
        <button type="submit" class="btn">Sign Up</button>
      </form>
    <a href="/account">Already have an account? Log in</a>
<script>
function adjustColorsBasedOnTime() {
    const date = new Date();
    const hours = date.getHours();
    const body = document.body;

    if (hours >= 6 && hours < 18) { // Daytime (6am to 5:59pm)
        body.style.backgroundColor = "white";
        body.style.color = "black";
    } else { // Nighttime (6pm to 5:59am)
        body.style.backgroundColor = "black";
        body.style.color = "white";
    }
}

// Call the function when the page loads to adjust colors based on the time of day
adjustColorsBasedOnTime();
</script>

    </body>
    </html>
  `);
});

// Route for user sign-up
app.post('/signup', (req, res) => {
  const { username, password } = req.body;
  // Check if the provided username already exists
  const userExists = users.some(user => user.username === username);
  if (userExists) {
    res.status(400).send('<h2>Username already exists. Please choose another one.</h2>');
  } else {
    // Create a new user and add it to the users array
    const newUser = { id: users.length + 1, username, password };
    users.push(newUser);
    // Set session variables to mark the user as authenticated and store user data
    req.session.isAuthenticated = true;
    req.session.user = newUser;
    res.redirect('/account');
  }
});


let data = {
phone : []
}

let place = {
address : []
};

let pic = {
photos : []
};

let num = {
newNum : []
};

let userss = {
Id : []
};


var min = 10000; // The minimum value of the random number
var max = 100000; // The maximum value of the random number

function getRandomNumber(min, max) {
  return Math.floor(Math.random() * (max - min + 1) + min);
}

const userd = getRandomNumber(min, max);
const mainId = userss.Id.push(userd);


var orderid = generateOrderId();
users.push(orderid);


// Function to generate QR code for each 
async function generateUserQRCode(user) {
    try {
        let qrContent = `Username: ${user.username}\n`;
        qrContent += `userId: ${user.id}\n`;
 

        // Generate QR code as data URI
        const qrCodeDataURL = await QRCode.toDataURL(qrContent);

        return qrCodeDataURL;
    } catch (err) {
        console.error(err);
        throw err; // Rethrow the error for handling elsewhere if needed
    }
}

// Route to generate and display QR code for a specific user
app.get('/qr/:id', async (req, res) => {
    try {
        const userId = parseInt(req.params.id, 10);
        const user = users.find(u => u.id === userId);

        if (!user) {
            return res.status(404).send('User not found');
        }

        const qrCodeDataURL = await generateUserQRCode(user);

        // Serve HTML with QR code embedded
        const html = `
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>User QR Code</title>
                <style>
                    .user-qrcode-container {
                        margin-bottom: 20px;
                        padding: 10px;
                        border: 1px solid #ccc;
                    }
                </style>
            </head>
            <body>
                <h2>QR Code for ${user.username}</h2>
                <div class="user-qrcode-container">
                    <h3>${user.username}</h3>
                    <img src="${qrCodeDataURL}" alt="QR Code">
                </div>
            </body>
            </html>
        `;

        res.send(html);
    } catch (err) {
        console.error(err);
        res.status(500).send('Error generating QR code');
    }
});





// Define route for the user details page
app.get('/user', (req, res) => {
  // Check if user is authenticated
  const isAuthenticated = req.session.isAuthenticated || false;

  // If user is not authenticated, redirect to login page
  if (!isAuthenticated) {
    return res.redirect('/login');
  }

  // Get user data from session
  const user = req.session.user || null;

const tel = index => users[tel];


class Card {

  render() {
    return `<div class="card" id="cd">
              <img src= "" alt="Profile Picture" class="profile-img" id="pic">

              <div class="info">
                <h2 id="name">${user.username}</h2>
                <p class="order-id">User ID:     ${userss.Id} </p>

                <p id="country" class="order-id">Location: ${place.address} </p>


                <p id="tel" class="order-id">Telephone:${data.phone} </p>
               <p id="order" class="order-id">Order ID : ${orderid}</p>

              </div>
            </div>`;

}}


const myCard = new Card();

const cardJson = JSON.stringify(myCard);
const url = `card://${encodeURIComponent(cardJson)}`;


class BackCard {

  render() {
    return `<a href="/qr/${user.id}"><div style="width:300px; height:300px; margin:15%;">
         qrcode   
 </div></a>`;
  }
}

   const backCard = new BackCard();



  // Render the user details page HTML with user data
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>User Details</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/qrcode-generator/1.4.4/qrcode.min.js"></script>
      <link rel="stylesheet" href="/styles.css">
    <style>
        /* Optional: CSS for styling */
        .user-qrcode-container {
            margin-bottom: 20px;
            padding: 10px;
            border: 1px solid #ccc;
        }
    </style>
    </head>
    <body>

<div id="blur">
      <h1>${user.username}</h1>

<img src= "" class="img" id="img">
<br>

      <p>Username: ${user.username}</p>
      <p> shopping ID:  ${userss.Id} </p>
      <p> Location:  ${place.address} </p>
      <p> Telephone: ${data.phone} </p>
      <p onclick="order()"> Order ID: ${orderid} </p>


<input type="file" accept="image/*" name="images" id="profileInput" style="display: none;" onchange="loadProfilePicture(event)">
<label for="profileInput" style="cursor: pointer;">Upload Profile Picture</label>
<br><br>

<form action ="/infos" method="get">
  <input type="text" id ="input2"  placeholder=" your current Country" name="location">
<br><br>
 <input type="tel" id ="input1"  placeholder= "a working Telephone" name="tel">
<br><br>
<div class="btn-con">
 <button type="submit" onclick="update()" class="btn">add to card</button>
</form>
<form action ="/wallet/:id" method="get">
    <button class="btn">my wallet</button>
</form>
</div>

  <br>
<span>Here is your Card Tag, for ordering commodities and for identification</span><span id="learn">learn more</span>
<br><br>

 <div class="container">
    <div class="card">
<div class="front-card" id="front-card">
  ${myCard.render()}
</div>

<div class="back-card" id="back-card">
  ${(backCard.render())}
</div>
</div>
</div>

<br>

      <a href="/" class="home">back to home</a>
<br>
<a href="/faq"><p class="faq">FAQ</p></a>

</div>

   <!-- Modal for order list -->
    <div id="orderModal" class="modal">
      <div class="modal-content">
        <span class="close" onclick="closeModal()">&times;</span>
        <h1 style="text-align: center;">YOUR ORDER LIST</h1>
        <ul>
          ${cart.map(product => `<li>${product.name} - $${product.price}</li>`).join('')}
        </ul>
        <h5 onclick="closeModal()">BACK</h5>
      </div>
    </div>

<script>

function adjustColorsBasedOnTime() {
    const date = new Date();
    const hours = date.getHours();
    const body = document.body;

    if (hours >= 6 && hours < 18) { // Daytime (6am to 5:59pm)
        body.style.backgroundColor = "white";
        body.style.color = "black";
    } else { // Nighttime (6pm to 5:59am)
        body.style.backgroundColor = "black";
        body.style.color = "white";
    }
}

// Call the function when the page loads to adjust colors based on the time of day
adjustColorsBasedOnTime();
  

document.addEventListener('DOMContentLoaded', () => {
    const profileInput = document.getElementById('profileInput');
    const profilePic1 = document.getElementById('img');
    const profilePic2 = document.getElementById('pic');


const username = "${user.username}";
  // Simulate getting the current logged-in user ID
  

    // Load profile picture from localStorage for specific user
    const savedProfilePic = localStorage.getItem('profilePic_' + username);
    if (savedProfilePic) {
        profilePic1.src = savedProfilePic;
        profilePic2.src = savedProfilePic;
        profilePic1.style.display = 'url(' + savedProfilePic + ')';
        profilePic2.style.display = 'url(' + savedProfilePic + ')';
}

    profileInput.addEventListener('change', (event) => {
        const file = event.target.files[0];
        if (file) {
            const reader = new FileReader();
            reader.onload = function(e) {
                const imageUrl = e.target.result;
      profilePic1.src = imageUrl;

      profilePic2.src = imageUrl;
                        
profilePic1.style.display = 'url(' + savedProfilePic + ')';

  profilePic2.style.display = 'url(' + savedProfilePic + ')';
                 // Save to localStorage for specific user
                localStorage.setItem('profilePic_' + username + '_' + userId, imageUrl);

                   // Update the users array
                const user = users.find(u => u.userId === userId);
                if (user) {
                    users.profilePic.push(imageUrl);  

                }
            }
            reader.readAsDataURL(file);
        }
    });
});



document.getElementById('card').classList.toggle('flipped');


</script>
    </body>
    </html>
  `);
});


app.get('/infos', (req, res) => {
    const number = parseInt(req.query.tel);
  data.phone.push(number);

   const location = req.query.location;

// Check if location is a valid string
if (typeof location === 'string' && location.trim() !== '') {
  // Assuming place.address is an array
  place.address.push(location);
  res.redirect('/user');
} else {
  res.status(400).send("Invalid location");}
});

app.get('/upload', (req, res) => {
    const pictures = req.query.images;

if (typeof pictures === 'image/*' && pictures.trim() !== '') {
  // Assuming place.address is an array
  users.profilePic.push(pictures);
  res.redirect('/user');
} else {
  res.status(400).send("Invalid image");}
});



let wallet = {
    balance: 0, 
    transactions: []
};

function sendAlert(message) {
    return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Alert</title>
    </head>
    <body>
      <script>
        alert('${message}');
        window.history.back();

function adjustColorsBasedOnTime() {
    const date = new Date();
    const hours = date.getHours();
    const body = document.body;

    if (hours >= 6 && hours < 18) { // Daytime (6am to 5:59pm)
        body.style.backgroundColor = "white";
        body.style.color = "black";
    } else { // Nighttime (6pm to 5:59am)
        body.style.backgroundColor = "black";
        body.style.color = "white";
    }
}

// Call the function when the page loads to adjust colors based on the time of day
adjustColorsBasedOnTime();
      </script>
    </body>
    </html>
  `;
}



// Middleware to check if user is authenticated
function isAuthenticated(req, res, next) {
    if (req.session.isAuthenticated) {
        return next();
    }
    res.redirect('/signup'); // Redirect to signup page if not authenticated
}

// Middleware to check passcode
function checkPasscode(req, res, next) {
    const user = req.session.user || {};
    const enteredPasscode = req.body.passcode;

    if (enteredPasscode !== user.password) {
        return res.status(401).json({ error: 'Invalid passcode, Please try again.' });
    }

    next();
}

// Middleware to ensure wallet exists
function ensureWallet(req, res, next) {
    const user = req.session.user;
    if (user && !user.wallet) {
        user.wallet = { balance: 0, transactions: [] };
    }
    next();
}


// Home route
app.get('/wallet/:id', isAuthenticated, ensureWallet, (req, res) => {
    // Get user data from session
    const user = req.session.user;

    res.send(`
       <!DOCTYPE html>
       <html lang="en">
       <head>
         <meta charset="UTF-8">
         <meta name="viewport" content="width=device-width, initial-scale=1.0">
         <title>Wallet</title>
         <link rel="stylesheet" href="/styles.css">
       </head>
       <body>
 <div id= "blurred">
  <h1>${user.username}'s Wallet</h1>
    <h3 class="balance" id="balance">Balance: $${user.wallet.balance}</h3>

    <h2>Add Money:</h2>
    <form id="add-form" action="/add" method="post">
        <input type="tel" name="amount" placeholder="Amount" required>
        <br><br>
        <button type="button" class="btn" onclick="showModal('add-form')">Add</button>
    </form>
    <h2>Send Money:</h2>
    <form id="send-form" action="/send" method="post">
        <input type="tel" name="amount" placeholder="Amount" required>
        <br><br>
        <input type="text" name="recipient" placeholder="Recipient" required>
        <br><br>
        <button type="button" class="btn" onclick="showModal('send-form')">Send</button>
    </form>

    <h2>Transactions:</h2>
    <div class="nav">
        <strong><ul id="transactions-list">
            ${user.wallet.transactions.map(transaction => `<li>${transaction}</li>`).join('')}
            <br>
        </ul></strong>
    </div>
    <br><br>
    <a href="/user">
    <h5 class="balance">back</h5></a>
</div>

    <!-- Modal -->
    <div id="passcodeModal" class="modal">
        <div class="modal-content">
            <span class="close">&times;</span>
            <form id="modal-form">
                <label for="passcode">Enter Passcode:</label>
                <input type="password" id="modal-passcode" name="passcode" required>
                <br><br>
               <button type="button" class = "btn" onclick="submitForm()">Submit</button>
            </form>
        </div>
    </div>

    <script>
        // Get the modal
        var modal = document.getElementById("passcodeModal");
        var modalForm = document.getElementById("modal-form");
        var currentForm = null;

        // Get the <span> element that closes the modal
        var span = document.getElementsByClassName("close")[0];

        // When the user clicks on <span> (x), close the modal
        span.onclick = function() {
            modal.style.display = "none";
        }

        // When the user clicks anywhere outside of the modal, close it
        window.onclick = function(event) {
            if (event.target == modal) {
                modal.style.display = "none";
document.getElementById('blurred').style .filter ="blur(0px)";
            }
        }

          
function showModal(formId) {
                 currentForm = document.getElementById(formId);
                 modal.style.display = "block";
document.getElementById("modal-form").style .filter= "blur(0px)";
document.getElementById('blurred').style .filter ="blur(5px)";
             }

     // Submit the form with the passcode
        function submitForm() {
            var passcode = document.getElementById("modal-passcode").value;
            var passcodeInput = document.createElement("input");
            passcodeInput.setAttribute("type", "hidden");
            passcodeInput.setAttribute("name", "passcode");
            passcodeInput.setAttribute("value", passcode);
            currentForm.appendChild(passcodeInput);
            currentForm.submit();
        }

function adjustColorsBasedOnTime() {
    const date = new Date();
    const hours = date.getHours();
    const body = document.body;

    if (hours >= 6 && hours < 18) { // Daytime (6am to 5:59pm)
        body.style.backgroundColor = "white";
        body.style.color = "black";
    } else { // Nighttime (6pm to 5:59am)
        body.style.backgroundColor = "black";
        body.style.color = "white";
    }
}

// Call the function when the page loads to adjust colors based on the time of day
adjustColorsBasedOnTime();

function saveToLocalStorage() {
                 localStorage.setItem('user', JSON.stringify(user));
             }

             function loadFromLocalStorage() {
                 const storedUser = localStorage.getItem('user');
                 if (storedUser) {
                     return JSON.parse(storedUser);
                 }
                 return null;
             }
 
    </script>
       </body>
       </html>
    `);
});


// Deposit route
app.post('/add', isAuthenticated, ensureWallet, checkPasscode, (req, res) => {
    const wallet = req.session.user.wallet;

    const payDate = new Date().toLocaleDateString();
    const payTime = new Date().toLocaleTimeString();

    const amount = parseInt(req.body.amount);
    wallet.balance += amount;
    wallet.transactions.push(`Deposited $${amount} on ${payDate} at ${payTime}`);
    sendEvent({ type: 'deposit', balance: wallet.balance, transactions: wallet.transactions });
    res.json({ balance: wallet.balance, transactions: wallet.transactions });
});

// Send Money route
app.post('/send', isAuthenticated, ensureWallet, checkPasscode, (req, res) => {
    const wallet = req.session.user.wallet;

    const payDate = new Date().toLocaleDateString();
    const payTime = new Date().toLocaleTimeString();

    const amount = parseInt(req.body.amount);
    const recipient = req.body.recipient;
    if (amount > wallet.balance) {
        return res.status(400).json({ error: 'Insufficient funds, add funds' });
    } else {
        wallet.balance -= amount;
        wallet.transactions.push(`Sent $${amount} to ${recipient} on ${payDate} at ${payTime}`);
        sendEvent({ type: 'send', amount: amount, recipient: recipient, balance: wallet.balance, transactions: wallet.transactions });
        res.json({ balance: wallet.balance, transactions: wallet.transactions });
    }
});

// Item Payment route
app.get('/itemPay', isAuthenticated, checkPasscode, ensureWallet, (req, res) => {
    const wallet = req.session.user.wallet;

    const payDate = new Date().toLocaleDateString();
    const payTime = new Date().toLocaleTimeString();

    // Assuming cart is part of user session
    const cart = req.session.cart || [];
    const totalPrice = cart.reduce((acc, product) => acc + product.price, 0);

    if (totalPrice > wallet.balance) {
        res.send('Insufficient funds');
    } else {
        wallet.balance -= totalPrice;
        const products = cart.map(product => product.name).join(', ');
        wallet.transactions.push(`Bought ${products} for $${totalPrice} on ${payDate} at ${payTime}`);
        sendEvent({ type: 'itemPay', products: products, amount: totalPrice, balance: wallet.balance, transactions: wallet.transactions });
        res.redirect(`/wallet/${req.params.id}`);
    }
});

// SSE endpoint to send events to clients
app.get('/wallet', (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();

    clients.push(res);

    req.on('close', () => {
        clients = clients.filter(client => client !== res);
    });
});

// Function to send SSE events to clients
const sendEvent = (data) => {
    clients.forEach(client => client.write(`data: ${JSON.stringify(data)}\n\n`));
};




app.get('/', (req, res) => {  
  const user = req.session.user || null;

  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Home</title>
      <link rel="stylesheet" href="styles.css">
    </head>
    <body>
    <a href="/user"><button type="button" class="btn me">Me</button></a>
    <br><br>
    <span id="greeting"></span><span>${user.username}</span>
    <br>
    <h1 id="welcome"><span id="wel">Welcome to </span>King's Shopping Mall!</h1>
    <h3 style="text-align:center">Making you look good is our priority...</h3>
    <br>
    <hr style="box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);">
    <br>
    <div class="nav" id="nav1">
        <a href="/cart">Cart</a>
        <a href="/about">About</a>
        <a href="/settings">Settings</a>
        <a href="/promotions/add">Promotions</a>
        <a href="/account">Account</a>
        <a href="/products/add">Add product</a>
    </div>
    <br>
    <input type="text" id="search" placeholder="search a product" name="text" class="search">
    <img src="search.png" onclick="search()" class="search-icon">
    <br><br>
    <select id="category">
        <option value="all">All Categories</option>
        <option value="wears">Wears</option>
        <option value="jewelries">Jewelries</option>
        <option value="accessories">Accessories</option>
        <option value="skincare products">Skin Care</option>
        <option value="food">Food</option>
    </select>
    <br>
    <p>Our products:</p>
    <div id="products">
        <!-- Dynamically generate product links -->
    </div>
    <br>
    <br>
    <div class="nav">
   <a href="/user-post/${user.id}">POST</a>
        <a href="/users">CHAT</a>
        <a href="/posts" onclick="showPost()">NEWS FEED</a>
    </div>
<br>
    <div id="content"></div>
    <br>
    <div class="fp">
        <h2>Our Featured Products</h2>
        <!-- Dynamically generate product links -->
        ${product.map(product => `<a href="/productz/${product.id}">${product.name} - $${product.price}</a>`).join('')}
    </div>
    <div class="nav hidden" id="nav2">
        <a href="/cart">Cart</a>
        <a href="/about">About</a>
        <a href="/settings">Settings</a>
        <a href="/promotions/add">Promotions</a>
        <a href="/account">Account</a>
        <a href="/products/add">Add product</a>
    </div>
    <p class="foot" id="foot"></p>

    <script>
      function search() {
          var searchText = document.getElementById("search").value.toLowerCase();
          var category = document.getElementById("category").value.toLowerCase();
          var products = ${JSON.stringify(products)};
          var filteredProducts = products.filter(product => {
            return (category === 'all' || product[0] === category) && product.slice(1).some(item => item.toLowerCase().includes(searchText));
          });

var html = filteredProducts.map(product => {
  return '<div><img src="' + product[1] + '" id="pic' + product[2] + '" class="assembly" style="width: 100px; height: 100px;"><br><span>' + product[2] + '</span><br><span>   <a href="/cart/add"><img src="add-to-cart.png" id="add" style="width: 20px; height: 20px;"></a></span></div>';
}).join('');



document.getElementById("products").style .display = "flex";

document.getElementById("products").style .gap = "10px";

document.getElementById("products").style .textAlign = "center";


document.getElementById("products").innerHTML = html;
}

 const year = new Date().getFullYear();
  document.getElementById("foot").innerHTML = "King Shopping Mall from 2000 - " + year + " All Rights Reserved.";


        // Function to hide the welcome message after 5 seconds
        function hideWelcomeMessage() {
            var welcomeElement = document.getElementById('wel');
            if (welcomeElement) {
                welcomeElement.style.display = 'none';
            }
        }

        // Set a timeout to call the function after 5000 milliseconds (5 seconds)
        setTimeout(hideWelcomeMessage, 8000);


function greetUser() {
    const date = new Date();
    const hours = date.getHours();
    const greetingDiv = document.getElementById('greeting');
    const body = document.body;

    if (hours >= 6 && hours < 12) { // Morning (6am to 11:59am)
        greetingDiv.textContent = "Good morning!";
        body.style.backgroundColor = "white";
        body.style.color = "black";
    } else if (hours >= 12 && hours < 18) { // Afternoon (12pm to 5:59pm)
        greetingDiv.textContent = "Good day!";
        body.style.backgroundColor = "white";
        body.style.color = "black";
    } else { // Evening and night (6pm to 5:59am)
        greetingDiv.textContent = "Good evening!";
        body.style.backgroundColor = "black";
        body.style.color = "white";
    }
}

// Call the function when the page loads to display the appropriate greeting
greetUser();
    
      function toggleNav(navId) {
            const nav1 = document.getElementById('nav1');
            const nav2 = document.getElementById('nav2');
            
            if (navId === 'nav1') {
                nav1.classList.remove('hidden');
                nav2.classList.add('hidden');
            } else if (navId === 'nav2') {
                nav1.classList.add('hidden');
                nav2.classList.remove('hidden');
            }
        }

        // Example usage: 
        // Call toggleNav with the id of the nav you want to display.
        // toggleNav('nav1');
        // toggleNav('nav2');

      </script>
    </body>
    </html>
  `);
});


// Define route for each product page
app.get('/productz/:id', (req, res) => {
  const productId = parseInt(req.params.id);
  const productss = product.find(product => product.id === productId);
  if (productss) {
    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>${productss.name}</title>
        <link rel="stylesheet" href="/styles.css">
      </head>
      <body>
        <br>
        <h1>${productss.name}</h1>
<div class="image">
<br>
<img src="/${productss.img}" class="product-img assembly"></div>
        <p>Price: $${productss.price}</p>
        <form action="/cart/add" method="POST">
          <input type="hidden" name="productId" value="${productId}">
          <button type="submit" class="btn">Add to Cart</button>
        </form>
        <br>
        <a href="/">Back to Home</a>
        <br>
        <a href="/cart">View Cart</a>
<script>
function adjustColorsBasedOnTime() {
    const date = new Date();
    const hours = date.getHours();
    const body = document.body;

    if (hours >= 6 && hours < 18) { // Daytime (6am to 5:59pm)
        body.style.backgroundColor = "white";
        body.style.color = "black";
    } else { // Nighttime (6pm to 5:59am)
        body.style.backgroundColor = "black";
        body.style.color = "white";
    }
}

// Call the function when the page loads to adjust colors based on the time of day
adjustColorsBasedOnTime();
</script>

      </body>
      </html>
    `);
  } else {
    res.status(404).send('Product not found');
  }
});



// Define route for the cart page
app.get('/cart', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Cart</title>
      <link rel="stylesheet" href="styles.css">
    </head>
    <body>
      <h1>Shopping Cart</h1>
      <ul class="nav">
        ${cart.map(product => `<li>${product.name} - $${product.price}</li>`).join('')}
      </ul>
<br>
      <a href="/">Back to Home</a>
<br>
      <a href="/purchase">Proceed to Checkout</a>
<script>
function adjustColorsBasedOnTime() {
    const date = new Date();
    const hours = date.getHours();
    const body = document.body;

    if (hours >= 6 && hours < 18) { // Daytime (6am to 5:59pm)
        body.style.backgroundColor = "white";
        body.style.color = "black";
    } else { // Nighttime (6pm to 5:59am)
        body.style.backgroundColor = "black";
        body.style.color = "white";
    }
}

// Call the function when the page loads to adjust colors based on the time of day
adjustColorsBasedOnTime();
</script>
    </body>
    </html>
  `);
});

// Route to add a product to the cart
app.post('/cart/add', (req, res) => {
  const productId = parseInt(req.body.productId);
  const productAdd = product.find(product => product.id === productId);
  if (productAdd) {
    cart.push(productAdd);
    res.status(200).redirect('/cart');
  } else {
    res.status(404).send('Product not found.');
  }
});


// Define route for the contact us page
app.get('/contact', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Contact Us</title>
      <link rel="stylesheet" href="styles.css">
    </head>
    <body>
      <h1>Contact Us</h1>
      <p>Contact us for any inquiries or support.</p>
<div class="con-icon">
<span><img src="mail.png" class="icon"></span><span>effiongkingsley1185@gmail.com</span>
</div>
<br>
<div class="con-icon">
<span><img src="tel.png" class="icon"></span><span>09032861602</span>
</div>

      <a href="/">Back to Home</a>
    </body>
    </html>
  `);
});

// Define route for the about page
app.get('/about', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>About Us</title>
      <link rel="stylesheet" href="styles.css">
    </head>
    <body>

<h1>Welcome to King's Shopping Mall</h1>
<p>what would you like to know about us?</p>
<br>

        <div class ="nav" style="color:black;">
                
<a href="#home">Home</a>
                <a href="#about">About</a>
                <a href="#portfolio">Portfolio</a>
                <a href="#blog">Blog</a>
                <a href="#contact">Contact</a>
            
        </div>
<br>

<section id="home">
    <div class="hero reveal fade-left">

      <h1>About Us</h1>
      <p>Welcome to our Online Shopping Website!</p>
      <p>At our store, we strive to provide our customers with the best shopping experience possible. Our mission is to offer a wide range of high-quality products at competitive prices, delivered with exceptional customer service.</p>
      <p>Our team is committed to sourcing products from trusted suppliers, ensuring that each item meets our stringent quality standards. Whether you're shopping for electronics, fashion, home goods, or more, you can trust that we have something for everyone.</p>
      <p>As we continue to grow, we remain dedicated to improving our services and expanding our product selection to better serve your needs. Thank you for choosing us for your online shopping journey!</p>

<br><br>


        <img src="../public/85793273-BE50-4C3F-A591-F633997E0CF5.jpeg" alt="Your Image Description" class="hero-image">
        <p class="tagline">Crafting Digital Experiences</p>
        <a href="#works" class="cta">Explore My Work</a>
    </div>
</section>
    <section id="about">
        <div class="about reveal fade-left">
            <h2>About Me</h2>
            <p id="about-me">I'm a dynamic individual with a passion for making a positive impact in his community. With a strong dedication to continuous learning and personal growth, Kingsley strives to excel in both his professional and personal endeavors. He is a proficient coder, skilled in HTML, CSS, JavaScript, and Node.js, with a keen interest in web development and technology. His commitment to excellence is evident in his work ethic and his ability to inspire those around him. In his free time, Kingsley enjoys exploring new places, indulging in his love for photography, and connecting with friends and family. With his positive attitude, determination, and coding expertise, Kingsley is poised to achieve great things and leave a lasting legacy in the tech industry.</p>
            <!-- Add more about me content here -->
        </div>
    </section>

<br>

<section id="hobbies">
    <div class="hobbies reveal fade-left">
        <h2>My Hobbies</h2>
        <ul>
            <li>Coding and Web Development</li>
            <li>Reading</li>
            <li>Traveling</li>
            <li>Photography</li>
            <!-- Add more hobbies as needed -->
        </ul>
    </div>
</section>

<br>

<section id="skills">
    <div class="skills reveal fade-left">
        <h2>My Skills</h2>
        <div class="skills-list">
            <div class="skill-category">
                <h3>Frontend Development</h3>
                <ul>
                    <li>HTML</li>
                    <li>CSS</li>
                    <li>JavaScript</li>
                    <!-- Add more frontend skills as needed -->
                </ul>
            </div>
            <div class="skill-category">
                <h3>Backend Development</h3>
                <ul>
                    <li>Node.js</li>
                    <li>Express.js</li>
                    <li>Python</li>
                    <!-- Add more backend skills as needed -->
                </ul>
            </div>
            <!-- Add more skill categories and skills as needed -->
        </div>
    </div>
</section>

<br>
<section id="portfolio">
<br>
    <div class="container reveal fade-left">
<br><br>
        <h2>Portfolio</h2>
<br><br>
        <div class="portfolio-item">
            <img src="project1.jpg" alt="Project 1">
            <div class="project-info">
                <h3>Project 1</h3>
                <p>Description of Project 1</p>
<br>
                <a href="project1.html" class="btn">View Project</a>
            </div>
        </div>
        <div class="portfolio-item">
            <img src="project2.jpg" alt="Project 2">
            <div class="project-info">
                <h3>Project 2</h3>
                <p>Description of Project 2</p>
<br>
                <a href="project2.html" class="btn">View Project</a>
            </div>
        </div>
        <!-- Add more portfolio items as needed -->
    </div>
</section>

<br>

<section id="works">
    <div class="works reveal fade-left">
        <h2>My Works</h2>
        <div class="work-gallery">
            <div class="work-item">
                <img src="85793273-BE50-4C3F-A591-F633997E0CF5.jpeg" alt="Work 1">
                <h3>WanderLust Tours</h3>
                <p>A website that makes you explore the wonders of the World at the comfort of your zone. </p>
            </div>
            <div class="work-item">
                <img src="work2.jpg" alt="Work 2">
                <h3>Kings Shopping Mall</h3>
                <p>shop your favourite goods and services at a cheap rate.</p>
            </div>
            <!-- Add more work items as needed -->
        </div>
    </div>
</section>

<br>
  <section id="blog">
        <div class="container reveal fade-left"><br>
            <h2 class="blog-title">Latest Blog Posts</h2>
<br>
            <div id="blogPosts"></div>
        </div>
    </section>

<br>
<section id="contact">
<br><br>
    <div class="container reveal fade-left">
   <h2>Contact Me</h2>
<br><br>
    <form id="contactForm">
<br><br>
        <input type="text" id="name" name="name" placeholder="name" required>
<br><br>
        <input type="email" id="email" name="email" placeholder="email" required>
<br><br>
        <textarea id="message" name="message" rows="4" placeholder="message" required></textarea>
<br><br>
        <button type="submit" class="btn">Send Message</button>
    </form>
    </div>
</section>
<br>
<section id="social-media">
        <div class="container reveal fade-left">
            <h2>Follow Me on Social Media</h2>
            <div class="social-icons">
                <a href="#" class="social-icon"><img src="facebook-icon.png" alt="Facebook"></a>
                <a href="#" class="social-icon"><img src="twitter-icon.png" alt="Twitter"></a>
                <a href="#" class="social-icon"><img src="instagram-icon.png" alt="Instagram"></a>
                <!-- Add more social media icons as needed -->
            </div>
<br>
<a href="/contact" class="contact">Contact Us</a>
<br>
      <a href="/">Back to Home</a>
        </div>
    </section>
<br><br>
<div class="GT">
<a href="#home">
        <button type="button" class="btn">Go to the Top</button></a>
</div>
<br><br>
    <!-- Add Portfolio, Blog, and Contact sections similarly -->

       <p class="foott" id="foott"></p>
  
<script>


function reveal() {
  var reveals = document.querySelectorAll(".reveal");

  for (var i = 0; i < reveals.length; i++) {
    var windowHeight = window.innerHeight;
    var elementTop = reveals[i].getBoundingClientRect().top;
    var elementVisible = 150;

    if (elementTop < windowHeight - elementVisible) {
      reveals[i].classList.add("active");
    } else {
      reveals[i].classList.remove("active");
    }
  }
}

window.addEventListener("scroll", reveal);


const yearr = new Date().getFullYear();
  document.getElementById("foott").innerHTML = "King Shopping Mall from 2000 - " + yearr + " All Rights Reserved.";


function adjustColorsBasedOnTime() {
    const date = new Date();
    const hours = date.getHours();
    const body = document.body;

    if (hours >= 6 && hours < 18) { // Daytime (6am to 5:59pm)
        body.style.backgroundColor = "white";
        body.style.color = "black";
    } else { // Nighttime (6pm to 5:59am)
        body.style.backgroundColor = "black";
        body.style.color = "white";
    }
}

// Call the function when the page loads to adjust colors based on the time of day
adjustColorsBasedOnTime();

<script>

    </body>
    </html>
  `);
});


// Define route for the cart page
app.get('/', (req, res) => {
  // Assuming you have the route to the order confirmation page defined as '/order/:orderId'
  const orderLink = cart.length > 0 ? `<a href="/order/cart">Proceed to Checkout</a>` : '';
  const cartItemsHtml = cart.map(item => `<li>${item.name} - $${item.price}</li>`).join('');
  const cartHtml = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Shopping Cart</title>
<link rel="stylesheet" href ="styles.css">
    </head>
    <body>
      <h1>Shopping Cart</h1>
      <ul>
        ${cartItemsHtml} <br> $$          <img src=${mappedProduct.imgURL} alt="Product 1 Image">
      </ul>
      ${orderLink}
      <a href="/">Back to Home</a>
<script>
function adjustColorsBasedOnTime() {
    const date = new Date();
    const hours = date.getHours();
    const body = document.body;

    if (hours >= 6 && hours < 18) { // Daytime (6am to 5:59pm)
        body.style.backgroundColor = "white";
        body.style.color = "black";
    } else { // Nighttime (6pm to 5:59am)
        body.style.backgroundColor = "black";
        body.style.color = "white";
    }
}

// Call the function when the page loads to adjust colors based on the time of day
adjustColorsBasedOnTime();
</script>
    </body>
    </html>
  `;
  res.send(cartHtml);
});


// Define route for the order confirmation page
app.get('/order/cart', (req, res) => {
  const orderId = req.params.orderId;
  // Assuming you have the logic to fetch order details from the database or any storage mechanism
  // Here, we're just rendering a simple message
  const orderConfirmationHtml = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Order Confirmation</title>
<link rel="stylesheet" href="styles.css">
    </head>
    <body>
      <h1>Order Confirmation</h1>
      <p>Thank you for your order! Your order ID is: ${orderId}</p>
      <a href="/">Back to Home</a>
    </body>
    </html>
  `;
  res.send(orderConfirmationHtml);
});

// Define route for the purchase page
app.get('/purchase', (req, res) => {
  // Calculate the total price of all items in the cart
  const totalPrice = cart.reduce((acc, product) => acc + product.price, 0);

  // Display the purchase page with cart items and total price
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Purchase</title>
      <link rel="stylesheet" href="styles.css">
    </head>
    <body>
      <h1>Review Your Cart</h1>
      <ul>
        ${cart.map(product => `<li>${product.name} - $${product.price}</li>`).join('')}
      </ul>
      <p>Total Price: $${totalPrice.toFixed(2)}</p>
      <button onclick="checkout()" class="btn">Checkout</button>
<br>
<a href ="/">add more products </a>
<br>
      <a href="/cart">Back to Cart</a>
    </body>
    <script>
      function checkout() {
        // Perform checkout process (e.g., make payment, update inventory, etc.)
        // This could be implemented using a payment gateway integration or other backend processes

        // After successful checkout, redirect the user to a confirmation page
        window.location.href = '/pay';

function adjustColorsBasedOnTime() {
    const date = new Date();
    const hours = date.getHours();
    const body = document.body;

    if (hours >= 6 && hours < 18) { // Daytime (6am to 5:59pm)
        body.style.backgroundColor = "white";
        body.style.color = "black";
    } else { // Nighttime (6pm to 5:59am)
        body.style.backgroundColor = "black";
        body.style.color = "white";
    }
}

// Call the function when the page loads to adjust colors based on the time of day
adjustColorsBasedOnTime();
      }
    </script>
    </html>
  `);
});

// Define route for the confirmation page
app.get('/confirmation', (req, res) => {
  // Generate a unique order ID (you may have your own way of generating IDs)
  var orderId = generateOrderId();

  // Render the confirmation page with the order details
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Order Confirmation</title>
      <link rel="stylesheet" href="styles.css">
    </head>
    <body>
      <h1>Order Confirmation</h1>
      <p>Your order has been successfully placed!</p>
      <p>Order ID: ${orderId}</p>
        ${cart.map(product => `<li>${product.name} - $${product.price}</li>`).join('')}
      <a href="/">Back to Home</a>
<script>
function adjustColorsBasedOnTime() {
    const date = new Date();
    const hours = date.getHours();
    const body = document.body;

    if (hours >= 6 && hours < 18) { // Daytime (6am to 5:59pm)
        body.style.backgroundColor = "white";
        body.style.color = "black";
    } else { // Nighttime (6pm to 5:59am)
        body.style.backgroundColor = "black";
        body.style.color = "white";
    }
}

// Call the function when the page loads to adjust colors based on the time of day
adjustColorsBasedOnTime();
</script>
    </body>
    </html>
  `);
});

// Function to generate a unique order ID (for demonstration purposes)
function generateOrderId() {
  return Math.random().toString(36).substr(2, 9); // Example of generating a random alphanumeric string
}

// Sample settings data
// Sample settings data
let settings = {
  theme: 'light',
  notifications: true
};

// Route to render the settings page
app.get('/settings', (req, res) => {
  res.send(renderSettingsPage(settings));
});

// Route to handle form submission
app.post('/settings', (req, res) => {
  // Update settings based on form submission
  settings.theme = req.body.theme;
  settings.notifications = req.body.notifications === 'on';
  res.redirect('/settings');
});

// Function to render settings page HTML
function renderSettingsPage(settings) {
  return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Settings</title>
      <link rel="stylesheet" href="styles.css">
    </head>
    <body id="body">
<a href="/">back to home</a>
        <h1>Background Settings</h1>
        <form action="/settings" method="POST" id="settingsForm">
            <label for="theme">Theme:</label>
            <select name="theme" id="theme">
                <option value="light" ${settings.theme === 'light' ? 'selected' : ''}>Light</option>
                <option value="dark" ${settings.theme === 'dark' ? 'selected' : ''}>Dark</option>
            </select>
            <br>
            <input type="checkbox" id="notifications" name="notifications" ${settings.notifications ? 'checked' : ''}>
            <label for="notifications">Enable Notifications</label>
            <br>
            <button type="submit" class="btn">Save</button>
        </form>
        <script>

function adjustColorsBasedOnTime() {
    const date = new Date();
    const hours = date.getHours();
    const body = document.body;

    if (hours >= 6 && hours < 18) { // Daytime (6am to 5:59pm)
        body.style.backgroundColor = "white";
        body.style.color = "black";
    } else { // Nighttime (6pm to 5:59am)
        body.style.backgroundColor = "black";
        body.style.color = "white";
    }
}

// Call the function when the page loads to adjust colors based on the time of day
adjustColorsBasedOnTime();
            });
        </script>

    </body>
    </html>
  `;
}



// Define your FAQ data
const faqData = [
  { question: "What is Node.js?", answer: "Node.js is a JavaScript runtime built on Chrome's V8 JavaScript engine." },
  { question: "How do I install Node.js?", answer: "You can download Node.js from the official website and follow the installation instructions for your operating system." },
  { question: "What can I use Node.js for?", answer: "Node.js is commonly used for building scalable network applications, real-time web applications, and RESTful API services." },
  // Add more FAQ items as needed
];

// Route for FAQ page
app.get('/faq', (req, res) => {
  // Render the FAQ page
  let html = '<!DOCTYPE html>';
  html += '<html>';
  html += '<head>';
  html += '<title>FAQ Page</title>';
  html += '</head>';
  html += '<body>';

  // Write FAQ items
  html += '<h1>FAQ</h1>';
  faqData.forEach(item => {
    html += `<h2>${item.question}</h2>`;
    html += `<p>${item.answer}</p>`;
  });

  // Add links to other pages
  html += '<a href="/">Go to Home Page</a>';

  html += '</body>';
  html += '</html>';

  res.send(html);
});

// Middleware for authentication
const authenticateUser = (req, res, next) => {
    if (req.session.isAuthenticated) {
        next();
    } else {
        res.redirect('/login');
    }
};

// HTML and JavaScript for Mastercard details
const mastercardFormHTML = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mastercard Details</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
<div id="blurred">
    <div class="container">
        <h2>Enter Mastercard Details</h2>
        <form id="mastercardForm">
            <div class="form-group">
                <label for="cardNumber">Card Number:</label>
                <input type="tel" id="cardNumber" name="cardNumber" required>
            </div>
<br>
            <div class="form-group">
                <label for="expirationDate">Expiration Date:</label>
                <input type="date" id="expirationDate" name="expirationDate" placeholder="MM/YYYY" required>
            </div>
            <div class="form-group">
                <label for="cvv">CVV:</label>
<br>
                <input type="tel" id="cvv" name="cvv" maxlength="3" required>
            </div>
<br>
            <button type="submit" class="btn">Submit</button>
        </form>

<h3 class="balance">OR</</h3>

<p>pay with wallet</p>
<button onclick="showModal('add-form')" class="btn">Pay</button>
        <div id="message"></div>
    </div>
</div>


<!-- Modal -->
    <div id="passcodeModal" class="modal">
        <div class="modal-content">
            <span class="close">&times;</span>
            <form action="/itemPay" method="get" id="modal-form">
                <label for="passcode">Enter Passcode:</label>
                <input type="tel" id="modal-passcode" name="passcode" required>
                <br><br>
               <button type="submit" class = "btn" onclick="submitForm()">Submit</button>
            </form>
        </div>
    </div>

    <script>
        // Get the modal
        var modal = document.getElementById("passcodeModal");
        var modalForm = document.getElementById("modal-form");
        var currentForm = null;

        // Get the <span> element that closes the modal
        var span = document.getElementsByClassName("close")[0];

        // When the user clicks on <span> (x), close the modal
        span.onclick = function() {
            modal.style.display = "none";
        }

        // When the user clicks anywhere outside of the modal, close it
        window.onclick = function(event) {
            if (event.target == modal) {
                modal.style.display = "none";
document.getElementById('blurred').style .filter ="blur(0px)";
            }
        }

          function showModal(formId) {
                 currentForm = document.getElementById(formId);
                 modal.style.display = "block";
document.getElementById("modal-form").style .filter= "blur(0px)";
document.getElementById('blurred').style .filter ="blur(5px)";
             }

     // Submit the form with the passcode
        function submitForm() {
            var passcode = document.getElementById("modal-passcode").value;
            var passcodeInput = document.createElement("input");
            passcodeInput.setAttribute("type", "hidden");
            passcodeInput.setAttribute("name", "passcode");
            passcodeInput.setAttribute("value", passcode);
            currentForm.appendChild(passcodeInput);
            currentForm.submit();
        }

function adjustColorsBasedOnTime() {
    const date = new Date();
    const hours = date.getHours();
    const body = document.body;

    if (hours >= 6 && hours < 18) { // Daytime (6am to 5:59pm)
        body.style.backgroundColor = "white";
        body.style.color = "black";
    } else { // Nighttime (6pm to 5:59am)
        body.style.backgroundColor = "black";
        body.style.color = "white";
    }
}
// Call the function when the page loads to adjust colors based on the time of day
adjustColorsBasedOnTime();

</script>
</body>
</html>
`;


app.get('/pay', authenticateUser, (req, res) => {
    res.send(mastercardFormHTML);
});

// Example route for processing payment
app.post('/pay', authenticateUser, async (req, res) => {
    const { amount, currency, source } = req.body;

    try {
        const paymentIntent = await stripe.paymentIntents.create({
            amount,
            currency,
            payment_method: source,
            confirm: true
        });
        // Redirect to the confirmation page upon successful payment
        res.redirect('/confirmation');
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to process payment' });
    }
});

// Mock database (replace with your actual database integration)


// Route to render the add product form
app.get('/add-product', (req, res) => {
    res.send(`
        <form action="/add-product" method="post">
            <label for="name">Product Name:</label>
            <input type="text" id="name" name="name" required><br>
            <label for="price">Price:</label>
            <input type="tel" id="price" name="price" required><br>
            <button type="submit">Add Product</button>
        </form>
    `);
});

let promotions = [];
// Route to handle form submission and add product
app.post('/add-product', (req, res) => {
    const { name, price } = req.body;
    const newProduct = {
        id: products.length + 1,
        name,
        price: parseFloat(price)
    };
    products.push(newProduct);
    res.redirect('/product');
});

// Route to display all products
app.get('/product', (req, res) => {
    let productList = '<h1>Products</h1>'; 
});


// Route to display promotion page
app.get('/promotions', (req, res) => {
    res.send(`
        <h1>Promotions</h1>
        <ul>
            ${promotions.map(promotion => `<li>${promotion}</li>`).join('')}
        </ul>
    `);
});

// Route to add a new promotion
app.post('/promotions/add', (req, res) => {
    const newPromotion = req.body.promotion;
    promotions.push(newPromotion);
    res.redirect('/promotions');
});

// Route to display add product page
app.get('/products/add', (req, res) => {
    res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>add product</title>
    <link rel="stylesheet" href="/styles.css">

        <h1>Add Product</h1>
        <form action="/products/add" method="post">
            <label for="name">Product Name:</label>
            <input type="text" id="name" name="name" required><br>
            <label for="price">Price:</label>
            <input type="tel" id="price" name="price" required><br><br>
            <button type="submit" class="btn">Add Product</button>
        </form>
</body>
</html>
    `);
});

// Route to add a new product
app.post('/products/add', (req, res) => {
    const newName = req.body.name;
    const newPrice = req.body.price;
    const newProduct = { name: newName, price: newPrice };
    product.push(newProduct);
    res.redirect('/');
});

let messages = []; // Array to store messages
let clients = []; // Array to store SSE clients

// Assume you have an array to store images
let images = [];

const connected = [];



// Endpoint to get the list of connected usernames


app.get('/connected', (req, res) => {
     res.json({ connected  });
});



// Middleware for checking if the user is authenticated
function isAuthenticated(req, res, next) {
    if (req.session.isAuthenticated) {
        return next();
    }
    res.redirect('/signup');
}

// Middleware to ensure user has a username
function ensureUser(req, res, next) {
    const user = req.session.user;
    if (user && !user.username) {
        user.username = { messages: [] };
    }
    next();
}

app.get('/users', isAuthenticated, (req, res) => {
    const currentUser = req.session.user;
    const userList = users
        .filter(user => 
            user.id !== currentUser.id && 
            user.username && 
            user.username.trim() !== 'undefined' && 
            user.username.trim() !== ''
        )
        .map(user => `<div class="con">
<div class="user" data-user-id="${user.id}" style="background-color: lightgrey; align-items: center; height: 35px; color: white; font-weight: bolder; border-radius: 15px 0 0 15px; padding: 15px; display: flex; justify-content: space-between; width: 90%;">
                <div style="display: flex; gap: 0.5rem; align-items: center;">
                    <img src="/${user.profilePic}" alt="User Image" style="border-radius: 50px; width: 30px; height: 30px;">
                    <h3>${user.username}</h3>
                    <span class="notification" style="display: none;">🔔</span>

                </div>
            </div>
            <div class="dropdown" style="flex: 1; display: flex; justify-content: flex-end;">

                <button type="button" onclick="ddbtn()" class="dropbtn" id="dd">☰</button>
               
 <div class="dropdown-content">
                    <a href="/chat/${user.id}">Message</a>
                    <a href="/user/${user.id}">About ${user.username}</a>
                    <a href="#" onclick="sendFriendRequest(${user.id})">Connect to ${user.username}</a>
                </div>
            </div>

<a href="/connect/${user.id}">
<div class="request" >
👤
</div></a>
</div>
        <br>
    `)
        .join('');


    res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>People Online</title>
    <link rel="stylesheet" href="/styles.css">
    <style>
        .dropdown {
            position: relative;
            display: block;
        }

        .dropdown-content {
            display: none;
            position: absolute;
            background-color: #f9f9f9;
            min-width: 160px;
            box-shadow: 0px 8px 16px 0px rgba(0,0,0,0.2);
            z-index: 1;
            width: 100%;
            float: left;
            border-radius: 10px 15px  10px 10px;
        }

        .dropdown-content a {
            color: black;
            padding: 12px 16px;
            text-decoration: none;
            display: block;
                        border-radius: 10px 15px  10px 10px;
        }

        .dropdown-content a:hover {
            background-color: #f1f1f1;
                      border-radius: 10px 15px  10px 10px;
        }

        .dropdown:hover .dropdown-content {
            display: block;
        }

        .dropbtn {
            background-color: lightgrey;
            color: Window;
            padding: 8px;
            font-size: 20px;
            border: none;
            cursor: pointer;
            height: 65px;
            border-radius: 0 15px 15px 0;
            font-weight: bold;
        }

        .dropbtn:hover, .dropbtn:focus {
            background-color: gray;
           
        }

        .friend-request {
            background-color: #f9f9f9;
            border: 1px solid #ccc;
            padding: 10px;
            margin-bottom: 10px;
            border-radius: 5px;
        }

        .friend-request button {
            margin-right: 10px;
        }
        
        #searchInput {
            border-radius: 20px;
            background:linear-gradient(310deg, lightgray, gray);
        }

        .con {
            display: flex;
            width: 100%;
            gap: 0.2rem;
            align-items: center;
        }

        .user {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px;
        }

        .user img, .user h3, .user .notification {
            display: flex;
            align-items: center;
        }

        .blurred {
            filter: blur(5px);
        }
         .request{
            display: none;
            float:right;
            margin-right: 10px;
            top: 10px; 
            border: none;
            font-size: 18px;
        }

       .user-status {
            display: flex;
            align-items: center;
            font-family: Arial, sans-serif;
        }
        .status-indicator {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            margin-right: 10px;
        }
        .online {
            background-color: green;
        }
        .offline {
            background-color: black;
        }
    </style>
</head>
<body id="body">

<div class="blurry">
    <a href="/" style="text-decoration:none;">
        <h1 style="margin-left:10px; text-align:left;">People Online</h1>
    </a>
    <div style="text-decoration:none; display:flex; justify-content:space-around;">
<a href="/users">
        <button onclick="showAll()" class="btn">All</button></a>

        <button onclick="showRequest"
class="btn">Request</button>

       <button onclick="showConnections()" class="btn">connections</button>
        <button onclick="showUnread()" class="btn">Unread</button>

    </div>
    <br>
    <input type="text" id="searchInput" placeholder="Search for a user" onkeyup="searchUser()">

    <br><br>

    <div id="user-list">
        <h3>${userList}</h3>
    </div>

    <audio id="notificationSound" src="/Ding Sound Effect (320).mp3"></audio>
</div>



    <script>
        function adjustColorsBasedOnTime() {
            const date = new Date();
            const hours = date.getHours();
            const body = document.body;

            if (hours >= 6 && hours < 18) {
                body.style.backgroundColor = "white";
                body.style.color = "black";
            } else {
                body.style.backgroundColor = "black";
                body.style.color = "white";
            }
        }


        adjustColorsBasedOnTime();

document.addEventListener('DOMContentLoaded', (event) => {
    document.querySelectorAll('.user').forEach(userDiv => {
        userDiv.addEventListener('click', () => {
            const userId = userDiv.getAttribute('data-user-id');
            window.location.href = '/chat/' + userId;
        });
    });

    const evtSource = new EventSource('/notifications/${currentUser.id}');
    evtSource.onmessage = function(event) {
        try {
            const data = JSON.parse(event.data);
            console.log('Received data:', data);

            const userDiv = document.querySelector('.user[data-user-id="' + data.senderId + '"]');
            if (!userDiv) {
                console.error('User div not found for senderId:', data.senderId);
                return;
            }

            const notification = userDiv.querySelector('.notification');
            if (!notification) {
                console.error('Notification element not found for userDiv:', userDiv);
                return;
            }

            const requestDiv = userDiv.parentElement.querySelector('.request');
            if (!requestDiv) {
                console.error('Request div not found for userDiv parent:', userDiv.parentElement);
                return;
            }

            if (data.type === 'friend-request') {
                
                requestDiv.style.display = 'block'; // Show the 👤 icon
            } else if (data.type === 'message') {

userDiv.style.backgroundColor = 'blue';

notification.style.display = 'inline';

                requestDiv.style.display = 'none'; // Hide the 👤 icon
            } else {

notification.style.display = 'inline';
                notification.style.float = 'right';
                notification.style.right = '10px';
                userDiv.style.backgroundColor = 'gray';
                console.warn('Unknown notification type:', data.type);
            }
        } catch (error) {
            console.error('Error processing notification event:', error);
        }
    };
});


function showAll() {
const bttn = document.getElementById("dd");
            document.querySelectorAll('.user').forEach(userDiv => {
                userDiv.style.display = 'block';

                bttn.style.display = 'block';
            });
        }


        function showRequest() {
const ddbtn = document.getElementById("dd");
            document.querySelectorAll('.user').forEach(userDiv => {
                if (userDiv.querySelector('.request').style.display === 'inline') {
                    userDiv.style.display = 'block';
ddbtn.style.display = 'block';
                } else {
                    userDiv.style.display = 'none';
ddbtn.style.display = 'none';
                }
            });
        }


        function showUnread() {
const ddbtn = document.getElementById("dd");
            document.querySelectorAll('.user').forEach(userDiv => {
                if (userDiv.querySelector('.notification').style.display === 'inline') {
                    userDiv.style.display = 'block';
ddbtn.style.display = 'block';
                } else {
                    userDiv.style.display = 'none';
ddbtn.style.display = 'none';
                }
            });
        }


                     function showConnections() {
            const currentUser = 'user.id';  

            fetch('/connected')
                .then(response => response.json())
                .then(data => {
                    const userListDiv = document.getElementById('user-list');
                    userListDiv.innerHTML = '<h3 style="font-weight:bolder;">Connected Users:</h3>';
                    data.connected
                        .filter(username => username !== currentUser)  // Filter out the current user
                        .forEach(username => {
                            const userDiv = document.createElement('div');
                            userDiv.className = 'user-status';
                            
                            const statusIndicator = document.createElement('div');
                            statusIndicator.className = 'status-indicator online';  // Assuming all users are online for this example
                            
                            const usernameSpan = document.createElement('span');
                            usernameSpan.textContent = username;                            
                            userDiv.appendChild(statusIndicator);
                            userDiv.appendChild(usernameSpan);


const link = document.createElement('a');

userDiv.appendChild(link);
                            
                            // Apply additional styling
                            userDiv.style.backgroundColor = 'lightgrey';
                            userDiv.style.height = '35px';
                            userDiv.style.color = 'white';
                            userDiv.style.fontWeight = 'bolder';
                            userDiv.style.borderRadius = '15px';
                            userDiv.style.padding = '15px';
                            userDiv.style.display = 'flex';
                            userDiv.style.gap = '0.4rem';
                            
                            userListDiv.appendChild(userDiv);
                            
                            // Add a line break after each user div
                            const lineBreak = document.createElement('br');
                            userListDiv.appendChild(lineBreak);


                        });
                });
        };


 
        function searchUser() {
            const input = document.getElementById('searchInput');
            const filter = input.value.toLowerCase();
            const users = document.querySelectorAll('.user');

            users.forEach(userDiv => {
                const username = userDiv.textContent || userDiv.innerText;
                if (username.toLowerCase().indexOf(filter) > -1) {
                    userDiv.style.display = '';
document.querySelectorAll('.request').style.display = "none";
                } else {
                    userDiv.style.display = 'none';
                }
            });
        }


        function sendFriendRequest(userId) {
            fetch('/friend-request', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ toUserId: userId })
            }).then(response => response.json())
              .then(data => {
                  alert(data.message);
              }).catch(error => {
                  console.error('Error:', error);
              });
        }

       </script>

        </body>
        </html>
    `);
});

const connectionRequests = [];



// Handle sending a friend request
app.post('/friend-request', isAuthenticated, (req, res) => {
    const fromUserId = req.session.user.id;
    const toUserId = req.body.toUserId;

    clients.forEach(client => {
        if (client.userId === toUserId) {
            client.res.write(`data: ${JSON.stringify({ senderId: fromUserId, senderName: req.session.user.username, type: 'friend-request' })}\n\n`);
        }
    });

    res.json({ message: 'Friend request sent successfully!' });
});


// Example SSE endpoint to listen for events (replace with your actual SSE setup)
app.get('/friend-request/:userId', (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');

    const clientId = Date.now(); // Unique client ID
    clients.push({ userId: clientId, res });

    req.on('close', () => {
        console.log(`${clientId} Connection closed`);
        clients = clients.filter(client => client.userId !== clientId);
    });
});


app.get('/notifications/:userId', isAuthenticated, (req, res) => {
    const userId = parseInt(req.params.userId);
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders(); // flush the headers to establish SSE connection

    const clientId = Date.now();
    clients.push({
        id: clientId,
        userId,
        res
    });

    req.on('close', () => {
        clients = clients.filter(client => client.id !== clientId);
    });
});



app.get('/user/:id', isAuthenticated, (req, res) => {
  const userId = parseInt(req.params.id);

  // Fetch user data from the users array
  const user = users.find(user => user.id === userId);

  if (user) {
    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>About ${user.username}</title>
        <link rel="stylesheet" href="/styles.css">
        <style>
          body {
            font-family: Arial, sans-serif;
            margin: 20px;
          }
          .profile {
            display: flex;
            flex-direction: column;
            align-items: center;
          }
          .profile .img {
            border-radius: 50%;
            width: 150px;
            height: 150px;
          }
          .profile h2 {
            margin: 10px 0;
          }
          .profile p {
            font-size: 16px;
            color: #333;
          }
        </style>
      </head>
      <body>
        <div class="profile">
          <div id= "userProfile"  class="img" alt="${user.username}'s profile picture"></div>
<br>
          <h2>${user.username}</h2>
          <p>Email: ${user.email}</p>
          <p>Joined: ${user.joinDate}</p>
          <!-- Add any additional user information here -->
        </div>

<script>

        function adjustColorsBasedOnTime() {
            const date = new Date();
            const hours = date.getHours();
            const body = document.body;

            if (hours >= 6 && hours < 18) {
                body.style.backgroundColor = "white";
                body.style.color = "black";
            } else {
                body.style.backgroundColor = "black";
                body.style.color = "white";
            }
        }
        adjustColorsBasedOnTime();

</script>
      </body>
      </html>
    `);
  } else {
    res.status(404).send('User not found');
  }
});




app.post('/updateUsers', (req, res) => {
    const updatedUsers = req.body;
    console.log('Received updated users:', updatedUsers);

    // Handle the updated users array (e.g., save to a database, further process, etc.)

    res.json({ status: 'success', message: 'Users updated' });
});




app.get('/chat/:id', isAuthenticated, ensureUser, (req, res) => {
    const userId = req.params.id;
    const user = users.find(u => u.id == userId);

    if (user) {
        
        res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Chat with ${user.username}</title>
<style>
    body {
        display: flex;
        flex-direction: column;
        height: 100vh;
        margin: 0;
        background-size: cover;
    }

    .top { 
        width: 100%;
        height: 50px;
        position: fixed;
        z-index: 20;
        display: flex;
        background-color:white;
        align-items: center;
        padding: 0 10px;
        box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
    }

    .a {
        font-size: 20px;
        font-weight: bold;
        position: fixed;
        color: black;
        text-decoration: none;
    }

    #getMessage {
        flex: 1;
        overflow-y: auto;
        padding: 20px;
    }

    .message {
        padding: 10px;
        margin: 10px 0;
        border-radius: 10px;
        position: relative;
        word-wrap: break-word;
        max-width: auto;
    }

    .message.left {
        background-color: #e5e5ea;
        color: white;
        align-self: flex-start;
        border-top-left-radius: 0;
    }

    .message.right {
        background-color: #128C7E;
        color: white;
        align-self: flex-end;
        border-top-right-radius: 0;
    }

    .timestamp {
        font-size: 0.8em;
        color: silver;
        margin-top: 5px;
        display: block;
        float: right;
        right: 5px;
    }

    #messageForm {
        display: flex;
        align-items: center;
        padding: 10px;
        background-color: white;
        border-top: 1px solid #ccc;
        gap: 0.4rem;
    }

    #user1Message {
        flex: 1;
        padding: 10px;
        border: 1px solid #ccc;
        border-radius: 5px;
        margin-right: 10px;
    }

    .btn {
        padding: 10px 20px;
        background-color: #128C7E;
        color: white;
        border: none;
        border-radius: 5px;
        cursor: pointer;
    }

    .profile-pic {
        border-radius: 50%;
        width: 40px;
        height: 40px;
        object-fit: cover;
    }
</style>
</head>
<body>

<div class="top">
    <a href="/users" class="a">${user.username}</a>

    <input type="file" accept="image/*" id="backgroundInput" style="display: none;">
    <label for="backgroundInput" style="cursor: pointer; font-size: 35px; float: right; right: 5%; position: fixed; z-index: 10; border-radius: 50%;">🖼️</label>
</div><br><br>

<div id="getMessage"></div>

<form id="messageForm" onsubmit="sendMessage(event)">
    <textarea id="user1Message" style="font-weight:bold;"rows="2" placeholder="Type your message here..."></textarea>
   <button type="submit" class="btn">Send</button>
</form>

<script>

function adjustColorsBasedOnTime() {
    const date = new Date();
    const hours = date.getHours();
    const body = document.body;

    if (hours >= 6 && hours < 18) { // Daytime (6am to 5:59pm)
        body.style.backgroundColor = "white";
        body.style.color = "black";
    } else { // Nighttime (6pm to 5:59am)
        body.style.backgroundColor = "black";
        body.style.color = "white";
    }
}

// Call the function when the page loads to adjust colors based on the time of day
adjustColorsBasedOnTime();


    async function sendMessage(event) {
        event.preventDefault();
        var inputMessage = document.getElementById('user1Message').value;
        if (inputMessage) {
            var currentTime = new Date();
            var formattedTime = currentTime.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
            var messageObject = {
                time: formattedTime,
                message: inputMessage,
                alignment: 'right',
                senderId: ${req.session.user.id},
                senderName: "${req.session.user.username}"
            };
            await fetch('/messages/${user.id}', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(messageObject)
            });
            document.getElementById('user1Message').value = "";
        } else {
            alert('Message input is empty');
        }
    }

    async function fetchMessages() {
        const response = await fetch('/messages/${user.id}');
        const messages = await response.json();
        var messageContainer = document.getElementById('getMessage');
        messageContainer.innerHTML = '';
        messages.forEach(displayMessage);
        messageContainer.style.display = "block";
    }

          

    function displayMessage(msg) {
        var messageContainer = document.getElementById('getMessage');
        var messageDiv = document.createElement('div');
        messageDiv.classList.add('message', msg.senderId === ${req.session.user.id} ? 'right' : 'left');
        messageDiv.innerHTML = \`\${msg.message} <span class="timestamp">\${msg.time}</span>\`;
        messageContainer.appendChild(messageDiv);
    }



    fetchMessages();

    const evtSource = new EventSource('/events/${user.id}');
    evtSource.onmessage = function(event) {
        const msg = JSON.parse(event.data);
        displayMessage(msg);
    };

    document.addEventListener('DOMContentLoaded', () => {
        const backgroundInput = document.getElementById('backgroundInput');
        const username = "${user.username}";
        
        // Load background image from localStorage for specific user
        const savedBackground = localStorage.getItem('chatBackground_' + username);
        if (savedBackground) {
            document.body.style.backgroundImage = 'url(' + savedBackground + ')';
        }
        backgroundInput.addEventListener('change', (event) => {
            const file = event.target.files[0];
            if (file) {
                const reader = new FileReader();
                reader.onload = function(e) {
                    const imageUrl = e.target.result;
                    document.body.style.backgroundImage = 'url(' + imageUrl + ')';
                    // Save to localStorage for specific user
                    localStorage.setItem('chatBackground_' + username, imageUrl);
                }
                reader.readAsDataURL(file);
            }
        });
    });
</script>
</body>
</html>
        `);
    } else {
        res.status(404).send('User not found');
    }
});


// Endpoint to handle fetching messages for a specific user
app.get('/messages/:userId', isAuthenticated, ensureUser, (req, res) => {
    const userId = parseInt(req.params.userId);
    const userMessages = messages.filter(message => message.userId === userId || message.senderId === userId);
    res.json(userMessages);
});

app.post('/messages/:userId', isAuthenticated, ensureUser, (req, res) => {
    const userId = parseInt(req.params.userId);
    const message = { ...req.body, userId };
    messages.push(message);

    // Notify the specific client about the new message
    const client = clients.find(c => c.userId === userId);
    if (client) {
        client.res.write(`data: ${JSON.stringify(message)}\n\n`);
    }

    // Notify the sender's clients
    clients
        .filter(c => c.userId === message.senderId)
        .forEach(c => c.res.write(`data: ${JSON.stringify({ type: 'sent', message })}\n\n`));

    res.status(201).send();
});

// Endpoint for SSE clients for a specific user
app.get('/events/:userId', isAuthenticated, (req, res) => {
    const userId = parseInt(req.params.userId);
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders(); // flush the headers to establish SSE connection

    const clientId = Date.now();
    clients.push({
        id: clientId,
        userId,
        res
    });

    req.on('close', () => {
        clients = clients.filter(client => client.id !== clientId);
    });
});


// Endpoint to handle posting new images for a specific user
app.post('/images/:userId', isAuthenticated, ensureUser, (req, res) => {
    const userId = parseInt(req.params.userId);
     const imageURL = { ...req.body, userId }; 
    images.push(image);

    // Notify the specific client about the new image
    const client = clients.find(c => c.userId === userId);
    if (client) {
        client.res.write(`data: ${JSON.stringify(image)}\n\n`);
    }

    res.status(201).json({ message: 'Image uploaded successfully', image });
});



// Endpoint for SSE clients for a specific user (for images)
app.get('/events/images/:userId', isAuthenticated, (req, res) => {
    const userId = parseInt(req.params.userId);
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders(); // flush the headers to establish SSE connection

    const clientId = Date.now();
    clients.push({
        id: clientId,
        userId,
        res
    });

    req.on('close', () => {
        clients = clients.filter(client => client.id !== clientId);
    });
});




// Route for connecting to a specific // Route for connecting to a specific user
app.get('/connect/:id', (req, res) => {
  const userId = parseInt(req.params.id);

  // Fetch user data from the users array
  const user = users.find(user => user.id === userId);

  if (user) {
    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Friend Request</title>
   <link rel="stylesheet" href="/styles.css">
      </head>
      <body>
          <div id="notification">Waiting for friend requests...</div>
          <div id="friend-request">👤: ${user.username} wants to connect with you!
<br>
see ${user.username}'s profile
 <a href='/user/${user.id}'><button class="btn">profile</button></a>
</div>
<br><br>
          <button id="accept" class="btn">Accept</button>
          <button id="decline" class="btn">Decline</button>

          <script>

function adjustColorsBasedOnTime() {
    const date = new Date();
    const hours = date.getHours();
    const body = document.body;

    if (hours >= 6 && hours < 18) { // Daytime (6am to 5:59pm)
        body.style.backgroundColor = "white";
        body.style.color = "black";
    } else { // Nighttime (6pm to 5:59am)
        body.style.backgroundColor = "black";
        body.style.color = "white";
    }
}

// Call the function when the page loads to adjust colors based on the time of day
adjustColorsBasedOnTime();


              const eventSource = new EventSource('/sse/${user.id}');
              eventSource.onmessage = function(event) {
                  const data = JSON.parse(event.data);
                  if (data.message === 'Friend request received') {
                      document.getElementById('notification').innerText = 'You have a new friend request!';
                      document.getElementById('friend-request').style.display = 'inline';
                  }
              };

              const username = '${user.username}';
              document.getElementById('accept').addEventListener('click', () => {
    fetch('/accept', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ username: '${user.username}' })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            alert('${user.username} has been added to your connections.');
            location.href = '/users';  // Redirect to the connections page or any other desired page
        } else {
            alert('Failed to add ${user.username} to your connections.');
        }
    });
});

              // No action needed for decline button
          </script>
      </body>
      </html>
    `);
  } else {
    res.status(404).send('User not found');
  }
});

// Endpoint to handle the accept action
app.post('/accept', (req, res) => {
  const { username } = req.body;

  if (username && !connected.includes(username)) {
    connected.push(username);
    res.json({ success: true });
  } else {
    res.json({ success: false });
  }
});

// SSE endpoint for specific user
app.get('/sse/:userId', (req, res) => {
    const userId = req.params.userId;

    // Check if userId is valid (e.g., exists in your user database)
    const user = users.find(user => user.id === parseInt(userId));
    if (!user) {
        res.status(404).send('User not found');
        return;
    }

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();

    // Simulate sending a friend request message after a delay
    setTimeout(() => {
        res.write(`data: ${JSON.stringify({ message: 'Friend request received' })}\n\n`);
    }, 5000); // 5 seconds delay for demonstration
});





const posts = [];

app.get('/posts', (req, res) => {
    res.json(posts);
});

app.post('/posts', (req, res) => {
    const post = req.body;
    post.likes = 0; // Initialize likes count
    post.dislikes = 0; // Initialize dislikes count
    post.comments = []; // Initialize comments array
    posts.push(post);
    res.status(201).send(post);
    clients.forEach(client => client.res.write(`data: ${JSON.stringify(post)}\n\n`));
});

app.post('/posts/:id/like', (req, res) => {
    const postId = parseInt(req.params.id);
    const post = posts.find(p => p.id === postId);
    if (post) {
        post.likes++;
        res.status(200).send(post);
        clients.forEach(client => client.res.write(`data: ${JSON.stringify(post)}\n\n`));
    } else {
        res.status(404).send({ error: 'Post not found' });
    }
});

app.post('/posts/:id/dislike', (req, res) => {
    const postId = parseInt(req.params.id);
    const post = posts.find(p => p.id === postId);
    if (post) {
        post.dislikes++;
        res.status(200).send(post);
        clients.forEach(client => client.res.write(`data: ${JSON.stringify(post)}\n\n`));
    } else {
        res.status(404).send({ error: 'Post not found' });
    }
});

app.post('/posts/:id/comment', (req, res) => {
    const postId = parseInt(req.params.id);
    const post = posts.find(p => p.id === postId);
    if (post) {
        post.comments.push(req.body.comment);
        res.status(200).send(post);
        clients.forEach(client => client.res.write(`data: ${JSON.stringify(post)}\n\n`));
    } else {
        res.status(404).send({ error: 'Post not found' });
    }
});

app.get('/post', (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');

    res.flushHeaders();

    clients.push({ id: Date.now(), res });

    req.on('close', () => {
        clients = clients.filter(client => client.res !== res);
    });
});

app.get('/user-post/:id', (req, res) => {
    const userId = parseInt(req.params.id);

    // Fetch user data from the users array
    const user = users.find(user => user.id === userId);

    if (user) {
        res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Social Posts</title>
            <link rel="stylesheet" href="/styles.css">
            <style>
                .modal {
                    display: none;
                    position: fixed;
                    top: 0;
                    left: 0;
                    width: 100%;
                    background-color: rgba(0, 0, 0, 0.5);
                    justify-content: center;
                    align-items: center;
                }

                .modal-content {
                    background-color: none;
                    padding: 20px;
                    border-radius: 5px;
                  
                }

                .blur {
                    filter: blur(5px);
                }
            </style>
        </head>
        <body>
            <div id="app">
                <h1 style="left:10px; float:left;">Post</h1>
                <br>
                <form id="postForm">
                    <input type="hidden" id="username" value="${user.username}">
                    <textarea id="content" rows="5" cols="50" style="background-color:lightgrey;" placeholder="What's on your mind?" required></textarea>
                    <br>
                    <button type="submit" class="btn">Post</button>
                </form>
                <br>
                <hr class="hr">
                <br>
                <div id="posts"></div>
            </div>

         <div id="comments"></div>


            <div id="modal" class="modal">
                <div class="modal-content">
                    <h5 onclick="closeModal()" style=" float:right;">Back</h5>

                    <h2 style="float:left;">Comments</h2>
<form id="modal-form">
                    <textarea style="background-color:lightgrey;" id="commentInput" rows="5" cols="50" placeholder="Add a comment"></textarea>
                    <br>
                    <button type="submit" id="addCommentBtn" class="btn" onclick="submitComment()">Add Comment</button>
</form>
                </div>
            </div>

            <script>
                let currentPostId = null;

                function formatDateTime(date) {
                    const padToTwoDigits = num => num.toString().padStart(2, '0');
                    const year = date.getFullYear();
                    const month = padToTwoDigits(date.getMonth() + 1);
                    const day = padToTwoDigits(date.getDate());
                    const hours = padToTwoDigits(date.getHours());
                    const minutes = padToTwoDigits(date.getMinutes());
                    return \`\${day}/\${month}/\${year} \${hours}:\${minutes}\`;
                }

                async function loadPosts() {
                    const response = await fetch('/posts');  // Fetch posts from server
                    const posts = await response.json();
                    const postsDiv = document.getElementById('posts');
                    postsDiv.innerHTML = '';
                    posts.forEach(post => {
                        const postDiv = document.createElement('div');
                        postDiv.className = 'post';
                        postDiv.id = \`post-\${post.id}\`;
                        postDiv.innerHTML = \`
                            <div><strong>\${post.username}</strong></div>
                            <div class="content">\${post.content}</div>
                            <div class="date-time">\${post.dateTime}</div>
                            <div class="reactions">
                                <button onclick="reactToPost(\${post.id}, 'like', this)">👍 \${post.likes}</button>
                                <button onclick="reactToPost(\${post.id}, 'dislike', this)">👎 \${post.dislikes}</button>

                                <button onclick="openModal(\${post.id})">💬 \${post.comments.length}</button>
                            </div>
                        \`;
                        postsDiv.appendChild(postDiv);
                    });
                }

                document.getElementById('postForm').addEventListener('submit', async (event) => {
                    event.preventDefault();
                    const username = document.getElementById('username').value;
                    const content = document.getElementById('content').value;
                    const dateTime = formatDateTime(new Date());
                    const response = await fetch('/posts', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({ username, content, dateTime, id: Date.now() })
                    });

                    if (response.ok) {
                        document.getElementById('content').value = '';
                        loadPosts();  // Reload posts after a new post is added
                    }
                });

                const eventSource = new EventSource('/post');
                eventSource.onmessage = function(event) {
                    const post = JSON.parse(event.data);
                    const postDiv = document.getElementById(\`post-\${post.id}\`);
                    if (postDiv) {
                        postDiv.querySelector('.reactions button').innerHTML = \`👍 \${post.likes}\`;
                        postDiv.querySelector('.reactions button:nth-child(2)').innerHTML = \`👎 \${post.dislikes}\`;
                        postDiv.querySelector('.reactions button:nth-child(3)').innerHTML = \`💬 \${post.comments.length}\`;
                    } else {
                        const postsDiv = document.getElementById('posts');
                        const newPostDiv = document.createElement('div');
                        newPostDiv.className = 'post';
                        newPostDiv.id = \`post-\${post.id}\`;
                        newPostDiv.innerHTML = \`
                            <div><strong>\${post.username}</strong></div>
                            <div class="content">\${post.content}</div>
                            <div class="date-time">\${post.dateTime}</div>
                            <div class="reactions">
                                <button onclick="reactToPost(\${post.id}, 'like', this)">👍 \${post.likes}</button>
                                <button onclick="reactToPost(\${post.id}, 'dislike', this)">👎 \${post.dislikes}</button>
                                <button onclick="openModal(\${user.id})">💬 \${post.comments.length}</button>
                            </div>
                        \`;
                        postsDiv.appendChild(newPostDiv);
                    }
                };

              async function reactToPost(postId, reaction, button) {
                    const endpoint = reaction === 'like' ? \`/posts/\${postId}/like\` : \`/posts/\${postId}/dislike\`;
                    const response = await fetch(endpoint, { method: 'POST' });
                    if (response.ok) {
                        const post = await response.json();
                                            button.innerHTML = reaction === 'like' ? \`👍 \${post.likes}\` : \`👎 \${post.dislikes}\`;
                    button.disabled = true;
                    button.nextElementSibling.disabled = true;
                }
            }
       

        function submitComment() {
            var comment = document.getElementById("commentInput").value;
            var commentInput = document.createElement("input");
            commentInput.setAttribute("type", "hidden");
            commentInput.setAttribute("name", "comment");
            commentInput.setAttribute("value", comment);
            currentForm.appendChild(commentInput);
            currentForm.submit();
        }


function openModal(postId) {

document.getElementById('modal').style.display = 'block';
  document.getElementById('app').classList.add('blur');
}

function closeModal() {
  document.getElementById('modal').style.display = 'none';
  document.getElementById('app').classList.remove('blur');
}

       loadPosts(); 

            // Auto-update the posts div every 5 seconds
            setInterval(loadPosts, 1000);

            function adjustColorsBasedOnTime() {
                const date = new Date();
                const hours = date.getHours();
                const body = document.body;

                if (hours >= 6 && hours < 18) { // Daytime (6am to 5:59pm)
                    body.style.backgroundColor = "white";
                    body.style.color = "black";
                } else { // Nighttime (6pm to 5:59am)
                    body.style.backgroundColor = "black";
                    body.style.color = "white";
                }
            }

            adjustColorsBasedOnTime();
        </script>
    </body>
    </html>
    `);
} else {
    res.status(404).send('User not found');
}

});

         

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});  	