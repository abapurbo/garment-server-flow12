require('dotenv').config();
const express = require('express')
const app = express()
const cors = require('cors');
const morgan = require('morgan')
const port = process.env.PORT || 4000;
const admin = require("firebase-admin");
const decoded = Buffer.from(process.env.FB_SERVICE_KEY, 'base64').toString('utf8')
const serviceAccount = JSON.parse(decoded);

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});
app.use(morgan('dev'))
app.use(express.json())
app.use(cors())

// user verify token in firebase
const verifyFBToken = async (req, res, next) => {
    const authorization = req.headers.authorization;
    console.log(authorization)
    if (!authorization) {
        return res.status(401).send({ message: "Unauthorized access" });
    }

    const token = authorization.split(" ")[1];
    if (!token) {
        return res.status(401).send({ message: 'Unauthorized access' })
    }
    try {
        const decoded = await admin.auth().verifyIdToken(token);
        req.decoded_email = decoded.email
        next();
    } catch (err) {
        return res.status(401).send({ message: 'Unauthorized access' })

    }


}
const { MongoClient, ServerApiVersion } = require('mongodb');
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.p9igsxk.mongodb.net/?appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

async function run() {
    const myDB = client.db('garmentFlowDb')
    const usersCollection = myDB.collection('users');
    const productCollection = myDB.collection('allProduct')
    try {
        // Connect the client to the server	(optional starting in v4.7)
        await client.connect();
        // admin verify 
        const adminVerify = async (req, res, next) => {
            const email = req.decoded_email
            const query = { email };
            const user = await usersCollection.findOne(query);

            if (!user || user.role !== 'admin') {
                return res.status(403).send({ message: 'forbidden access' });
            }

            next();
        }
        // manager verify 
        const managerVerify = async (req, res, next) => {
            const email = req.decoded_email
            const query = { email };
            const user = await usersCollection.findOne(query);

            if (!user || user.role !== 'manager') {
                return res.status(403).send({ message: 'forbidden access' });
            }

            next();
        }
        // get a user role 
        app.get('/users/:email/role', async (req, res) => {
            const email = req.params.email;
            const query = { email }
            const user = await usersCollection.findOne(query);
            res.send({ role: user?.role || 'buyer' })
        })
        // add products
        app.post('/add-product', verifyFBToken, managerVerify, async (req, res) => {
            const product = req.body;
            console.log(product)
        })
        // create user api
        app.post('/user', async (req, res) => {
            const user = req.body;
            // Default Role
            const role = user.role || 'buyer';
            const email = user.email;
            // Check if already exists
            const existingUser = await usersCollection.findOne({ email });

            if (existingUser) {
                return res.send({ message: 'user already exists' });
            }

            // Prepare new user
            const newUser = {
                ...user,
                role,
                createdAt: new Date()
            };

            const result = await usersCollection.insertOne(newUser);
            res.send(result);
        });

        // get users api
        app.get('/users', verifyFBToken, adminVerify, async (req, res) => {
            const resutl = await usersCollection.find().toArray();
            res.send(resutl)
        })





        // Send a ping to confirm a successful connection
        await client.db("admin").command({ ping: 1 });
        console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } finally {
        // Ensures that the client will close when you finish/error
        // await client.close();
    }
}
run().catch(console.dir);



app.get('/', (req, res) => {
    res.send('garmentflow server site is runing....')
})

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})
